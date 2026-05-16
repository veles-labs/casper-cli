use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, ValueEnum};
use comfy_table::{Cell, Table};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use tinytemplate::TinyTemplate;
use zeroize::Zeroize;

use crate::network;
use crate::storage::StorageConfig;

use super::{
    AccountDeriver, DerivationScheme, DerivedAccountCandidate, WalletType, add_account,
    derivation_index_limit, derive_secret_key_for_path, ensure_wallet_exists, load_metadata,
    root_seed, save_metadata, secret_key_bytes, wallet_storage,
};

const DEFAULT_MAX_ATTEMPTS: u64 = 1_000_000;
const PROGRESS_UPDATE_INTERVAL: u64 = 1024;

#[derive(Args)]
/// Arguments for finding vanity accounts by scanning derivation paths.
pub struct DeriveVanityArgs {
    /// Name of the wallet.
    wallet_name: String,
    /// Match targets that start with this lowercase-normalized text.
    #[arg(long, value_name = "TEXT")]
    starts_with: Option<String>,
    /// Match targets that end with this lowercase-normalized text.
    #[arg(long, value_name = "TEXT")]
    ends_with: Option<String>,
    /// Match targets with this regular expression.
    #[arg(long, value_name = "PATTERN")]
    regex: Option<String>,
    /// Value to apply vanity matchers to.
    #[arg(long, value_enum, default_value = "account-hash")]
    target: VanityTarget,
    /// Starting index for derivation path scanning.
    #[arg(long, default_value_t = 0)]
    start: u32,
    /// Number of matching accounts to save.
    #[arg(long, default_value_t = 1)]
    count: usize,
    /// Maximum candidate derivations to attempt (default: 1000000 unless --unbounded).
    #[arg(long, conflicts_with = "unbounded", value_name = "N")]
    max_attempts: Option<u64>,
    /// Continue until enough matches are found or the derivation index space is exhausted.
    #[arg(long)]
    unbounded: bool,
    /// Number of Rayon worker threads to use.
    #[arg(long, value_name = "N")]
    jobs: Option<usize>,
    /// Account name template for found accounts.
    #[arg(long, default_value = "vanity-{index}", value_name = "TEMPLATE")]
    name: String,
    /// Print private keys for found accounts (dangerous).
    #[arg(long, alias = "private")]
    show_private: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum VanityTarget {
    AccountHash,
    PublicKey,
}

impl VanityTarget {
    fn value_from_candidate(self, candidate: &DerivedAccountCandidate) -> &str {
        match self {
            Self::AccountHash => &candidate.account_hash_hex,
            Self::PublicKey => &candidate.public_key_hex,
        }
    }
}

#[derive(Clone, Copy)]
enum AttemptLimit {
    Bounded(u64),
    Unbounded,
}

impl AttemptLimit {
    fn max_attempts(self) -> Option<u64> {
        match self {
            Self::Bounded(max_attempts) => Some(max_attempts),
            Self::Unbounded => None,
        }
    }
}

#[derive(Debug)]
struct VanityMatcher {
    starts_with: Option<String>,
    ends_with: Option<String>,
    regex: Option<Regex>,
    target: VanityTarget,
}

impl VanityMatcher {
    fn new(
        starts_with: Option<String>,
        ends_with: Option<String>,
        regex: Option<String>,
        target: VanityTarget,
    ) -> Result<Self> {
        let starts_with = normalize_affix(starts_with, "--starts-with")?;
        let ends_with = normalize_affix(ends_with, "--ends-with")?;
        let regex = match regex {
            Some(pattern) if pattern.is_empty() => bail!("--regex cannot be empty"),
            Some(pattern) => {
                Some(Regex::new(&pattern).with_context(|| format!("invalid --regex '{pattern}'"))?)
            }
            None => None,
        };

        if starts_with.is_none() && ends_with.is_none() && regex.is_none() {
            bail!("provide at least one of --starts-with, --ends-with, or --regex");
        }

        Ok(Self {
            starts_with,
            ends_with,
            regex,
            target,
        })
    }

    fn matches(&self, candidate: &DerivedAccountCandidate) -> bool {
        let value = self.target.value_from_candidate(candidate);
        self.matches_value(value)
    }

    fn matches_value(&self, value: &str) -> bool {
        if let Some(starts_with) = &self.starts_with
            && !value.starts_with(starts_with)
        {
            return false;
        }
        if let Some(ends_with) = &self.ends_with
            && !value.ends_with(ends_with)
        {
            return false;
        }
        if let Some(regex) = &self.regex
            && !regex.is_match(value)
        {
            return false;
        }
        true
    }
}

#[derive(Serialize)]
struct VanityNameContext<'a> {
    counter: u32,
    counter1: u32,
    index: u32,
    index1: u32,
    wallet: &'a str,
    network: &'a str,
    chain_name: &'a str,
}

struct SearchOutcome {
    matches: Vec<DerivedAccountCandidate>,
    attempts: u64,
    exhausted_attempts: bool,
    exhausted_indexes: bool,
}

pub fn handle(
    storage: &StorageConfig,
    context: &network::ConfigContext,
    args: DeriveVanityArgs,
) -> Result<()> {
    let matcher = VanityMatcher::new(
        args.starts_with.clone(),
        args.ends_with.clone(),
        args.regex.clone(),
        args.target,
    )?;
    if args.count == 0 {
        bail!("--count must be greater than 0");
    }
    let attempt_limit = if args.unbounded {
        AttemptLimit::Unbounded
    } else {
        let max_attempts = args.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);
        if max_attempts == 0 {
            bail!("--max-attempts must be greater than 0");
        }
        AttemptLimit::Bounded(max_attempts)
    };
    let jobs = args.jobs.unwrap_or_else(default_parallelism);
    if jobs == 0 {
        bail!("--jobs must be greater than 0");
    }

    let wallet_storage = wallet_storage(storage, &args.wallet_name)?;
    ensure_wallet_exists(&wallet_storage, &args.wallet_name)?;
    let mut metadata = load_metadata(&wallet_storage.metadata_path)?;
    if matches!(&metadata.wallet_type, WalletType::LegacyPem { .. }) {
        bail!("legacy secret key wallets do not support account derivation");
    }

    let name_template = args.name.as_str();
    if name_template.is_empty() {
        bail!("account name template cannot be empty");
    }
    let (network_name, chain_name) = network::active_network_name_and_chain_name(context)?;
    let root_secret = wallet_storage
        .storage
        .load(&args.wallet_name)
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut seed = root_seed(&root_secret)?;

    let result = (|| -> Result<()> {
        let existing_paths = metadata
            .accounts
            .iter()
            .map(|account| account.path.clone())
            .collect::<HashSet<_>>();
        let progress = vanity_progress_bar(attempt_limit, args.count)?;
        let outcome = search_vanity_matches(
            &seed,
            metadata.derivation,
            args.start,
            args.count,
            attempt_limit,
            jobs,
            &existing_paths,
            &matcher,
            &progress,
        );
        progress.finish_and_clear();
        let outcome = outcome?;

        let mut updated = false;
        let names = render_match_names(
            &outcome.matches,
            name_template,
            &args.wallet_name,
            &network_name,
            &chain_name,
            &metadata
                .accounts
                .iter()
                .map(|account| account.name.clone())
                .collect::<HashSet<_>>(),
        )?;

        let mut table = Table::new();
        table.set_header(vec!["Name", "Path", "Account Hash"]);
        for (candidate, name) in outcome.matches.iter().zip(names.iter()) {
            table.add_row(vec![
                Cell::new(name),
                Cell::new(&candidate.path),
                Cell::new(&candidate.account_hash_hex),
            ]);

            if args.show_private {
                let secret_key =
                    derive_secret_key_for_path(&seed, metadata.derivation, &candidate.path)?;
                let mut private_key_bytes = secret_key_bytes(&secret_key)?;
                println!("Private key: {}", hex::encode(&private_key_bytes));
                private_key_bytes.zeroize();
            }

            if add_account(
                &mut metadata,
                name,
                candidate.index,
                &candidate.path,
                &candidate.public_key_hex,
            ) {
                updated = true;
            }
        }

        if updated {
            save_metadata(&wallet_storage.metadata_path, &metadata)?;
        }

        if !outcome.matches.is_empty() {
            println!("{table}");
        }
        println!(
            "Found {} of {} requested match(es) after {} candidate attempt(s).",
            outcome.matches.len(),
            args.count,
            outcome.attempts
        );

        if outcome.matches.len() < args.count {
            let reason = if outcome.exhausted_attempts {
                "exhausting the candidate attempt limit"
            } else if outcome.exhausted_indexes {
                "exhausting the derivation index space"
            } else {
                "stopping early"
            };
            bail!(
                "found {} of {} requested match(es) before {reason}",
                outcome.matches.len(),
                args.count
            );
        }

        Ok(())
    })();
    seed.zeroize();
    result
}

#[allow(clippy::too_many_arguments)]
fn search_vanity_matches(
    seed: &[u8],
    derivation: DerivationScheme,
    start: u32,
    count: usize,
    attempt_limit: AttemptLimit,
    jobs: usize,
    existing_paths: &HashSet<String>,
    matcher: &VanityMatcher,
    progress: &ProgressBar,
) -> Result<SearchOutcome> {
    if jobs == 0 {
        bail!("--jobs must be greater than 0");
    }

    let index_limit = derivation_index_limit(derivation);
    if u64::from(start) >= index_limit {
        return Ok(SearchOutcome {
            matches: Vec::new(),
            attempts: 0,
            exhausted_attempts: false,
            exhausted_indexes: true,
        });
    }

    let pool = ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("failed to build Rayon thread pool")?;
    let next_index = AtomicU64::new(u64::from(start));
    let attempts = AtomicU64::new(0);
    let found = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let exhausted_attempts = AtomicBool::new(false);
    let exhausted_indexes = AtomicBool::new(false);
    let matches = Mutex::new(Vec::new());
    let error = Mutex::new(None);
    let max_attempts = attempt_limit.max_attempts();

    pool.install(|| {
        (0..jobs).into_par_iter().for_each(|_| {
            let deriver = match AccountDeriver::new(seed, derivation) {
                Ok(deriver) => deriver,
                Err(err) => {
                    record_error(&error, err, &done);
                    return;
                }
            };

            loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }

                let index = next_index.fetch_add(1, Ordering::Relaxed);
                if index >= index_limit {
                    exhausted_indexes.store(true, Ordering::Relaxed);
                    done.store(true, Ordering::Relaxed);
                    break;
                }

                let index = index as u32;
                let path = match deriver.path_for_index(index) {
                    Ok(path) => path,
                    Err(err) => {
                        record_error(&error, err, &done);
                        break;
                    }
                };
                if existing_paths.contains(&path) {
                    continue;
                }

                let Some(attempt_number) = reserve_attempt(&attempts, max_attempts) else {
                    exhausted_attempts.store(true, Ordering::Relaxed);
                    done.store(true, Ordering::Relaxed);
                    break;
                };

                let candidate = match deriver.derive_candidate(index, path) {
                    Ok(candidate) => candidate,
                    Err(err) => {
                        progress.inc(1);
                        record_error(&error, err, &done);
                        break;
                    }
                };
                progress.inc(1);
                if attempt_number % PROGRESS_UPDATE_INTERVAL == 0 {
                    progress.set_message(progress_message(found.load(Ordering::Relaxed), count));
                }

                if !matcher.matches(&candidate) {
                    continue;
                }

                if let Ok(previous) =
                    found.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        (value < count).then_some(value + 1)
                    })
                {
                    if let Ok(mut matches) = matches.lock() {
                        matches.push(candidate);
                    } else {
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                    let new_found = previous + 1;
                    progress.set_message(progress_message(new_found, count));
                    if new_found >= count {
                        done.store(true, Ordering::Relaxed);
                    }
                }
            }
        });
    });

    if let Some(err) = error
        .lock()
        .map_err(|_| anyhow!("vanity search error lock poisoned"))?
        .take()
    {
        return Err(err);
    }

    let mut matches = matches
        .into_inner()
        .map_err(|_| anyhow!("vanity search matches lock poisoned"))?;
    matches.sort_by_key(|candidate| candidate.index);

    Ok(SearchOutcome {
        matches,
        attempts: attempts.load(Ordering::Relaxed),
        exhausted_attempts: exhausted_attempts.load(Ordering::Relaxed),
        exhausted_indexes: exhausted_indexes.load(Ordering::Relaxed),
    })
}

fn reserve_attempt(attempts: &AtomicU64, max_attempts: Option<u64>) -> Option<u64> {
    loop {
        let current = attempts.load(Ordering::Relaxed);
        if max_attempts.is_some_and(|max_attempts| current >= max_attempts) {
            return None;
        }
        let next = current.checked_add(1)?;
        if attempts
            .compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return Some(next);
        }
    }
}

fn render_match_names(
    matches: &[DerivedAccountCandidate],
    name_template: &str,
    wallet_name: &str,
    network_name: &str,
    chain_name: &str,
    existing_names: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut names = TinyTemplate::new();
    names
        .add_template("name", name_template)
        .map_err(|err| anyhow!("invalid account name template: {err}"))?;
    let mut seen_names = existing_names.clone();
    let mut rendered = Vec::with_capacity(matches.len());

    for (ordinal, candidate) in matches.iter().enumerate() {
        let counter =
            u32::try_from(ordinal).map_err(|_| anyhow!("counter overflows for match {ordinal}"))?;
        let counter1 = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("counter1 overflows for match {ordinal}"))?;
        let index1 = candidate
            .index
            .checked_add(1)
            .ok_or_else(|| anyhow!("index1 overflows for index {}", candidate.index))?;
        let context = VanityNameContext {
            counter,
            counter1,
            index: candidate.index,
            index1,
            wallet: wallet_name,
            network: network_name,
            chain_name,
        };
        let name = names.render("name", &context).map_err(|err| {
            anyhow!(
                "failed to render account name for index {}: {err}",
                candidate.index
            )
        })?;
        if name.is_empty() {
            bail!("derived account name cannot be empty");
        }
        if name.starts_with('-') {
            bail!("derived account name cannot start with '-'");
        }
        if !seen_names.insert(name.clone()) {
            bail!("account name '{name}' already exists");
        }
        rendered.push(name);
    }

    Ok(rendered)
}

fn normalize_affix(value: Option<String>, flag: &str) -> Result<Option<String>> {
    match value {
        Some(value) if value.is_empty() => bail!("{flag} cannot be empty"),
        Some(value) => Ok(Some(value.to_ascii_lowercase())),
        None => Ok(None),
    }
}

fn vanity_progress_bar(attempt_limit: AttemptLimit, count: usize) -> Result<ProgressBar> {
    let progress = match attempt_limit {
        AttemptLimit::Bounded(max_attempts) => ProgressBar::new(max_attempts),
        AttemptLimit::Unbounded => ProgressBar::new_spinner(),
    };
    let style = match attempt_limit {
        AttemptLimit::Bounded(_) => {
            ProgressStyle::with_template("{msg} [{bar:40}] {pos}/{len} attempts ({per_sec})")
        }
        AttemptLimit::Unbounded => {
            ProgressStyle::with_template("{spinner} {msg} {pos} attempts ({per_sec})")
        }
    }
    .context("failed to set progress bar style")?
    .progress_chars("=>-");
    progress.set_style(style);
    progress.set_message(progress_message(0, count));
    Ok(progress)
}

fn progress_message(found: usize, count: usize) -> String {
    format!("Found {found}/{count}")
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

fn record_error(error: &Mutex<Option<anyhow::Error>>, err: anyhow::Error, done: &AtomicBool) {
    if let Ok(mut error) = error.lock()
        && error.is_none()
    {
        *error = Some(err);
    }
    done.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::super::derive_account_candidate;
    use super::*;

    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn match_any() -> VanityMatcher {
        VanityMatcher::new(None, None, Some(".".to_string()), VanityTarget::AccountHash)
            .expect("matcher")
    }

    #[test]
    fn matcher_requires_at_least_one_filter() {
        let err = VanityMatcher::new(None, None, None, VanityTarget::AccountHash)
            .expect_err("missing matcher should fail");
        assert!(
            err.to_string()
                .contains("provide at least one of --starts-with")
        );
    }

    #[test]
    fn matcher_normalizes_affixes_and_ands_filters() {
        let matcher = VanityMatcher::new(
            Some("AB".to_string()),
            Some("EF".to_string()),
            Some("cd".to_string()),
            VanityTarget::AccountHash,
        )
        .expect("matcher");
        assert!(matcher.matches_value("abcdef"));
        assert!(!matcher.matches_value("abcdee"));
        assert!(!matcher.matches_value("00cdef"));
    }

    #[test]
    fn matcher_rejects_invalid_regex() {
        let err = VanityMatcher::new(None, None, Some("(".to_string()), VanityTarget::AccountHash)
            .expect_err("invalid regex should fail");
        assert!(err.to_string().contains("invalid --regex"));
    }

    #[test]
    fn candidate_paths_match_derivation_scheme() {
        let bip32 = derive_account_candidate(&TEST_SEED, DerivationScheme::Bip32Secp256k1, 5)
            .expect("bip32 candidate");
        assert_eq!(bip32.path, "m/44'/506'/0'/0/5");

        let slip10 = derive_account_candidate(&TEST_SEED, DerivationScheme::Slip10Ed25519, 5)
            .expect("slip10 candidate");
        assert_eq!(slip10.path, "m/44'/506'/0'/0'/5'");
    }

    #[test]
    fn bounded_search_returns_partial_matches() {
        let outcome = search_vanity_matches(
            &TEST_SEED,
            DerivationScheme::Bip32Secp256k1,
            0,
            2,
            AttemptLimit::Bounded(1),
            1,
            &HashSet::new(),
            &match_any(),
            &ProgressBar::hidden(),
        )
        .expect("search");
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.attempts, 1);
        assert!(outcome.exhausted_attempts);
    }

    #[test]
    fn search_skips_existing_paths_without_consuming_attempts() {
        let mut existing_paths = HashSet::new();
        existing_paths.insert("m/44'/506'/0'/0/0".to_string());

        let outcome = search_vanity_matches(
            &TEST_SEED,
            DerivationScheme::Bip32Secp256k1,
            0,
            1,
            AttemptLimit::Bounded(1),
            1,
            &existing_paths,
            &match_any(),
            &ProgressBar::hidden(),
        )
        .expect("search");
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].index, 1);
        assert_eq!(outcome.attempts, 1);
    }

    #[test]
    fn search_stops_when_start_is_outside_bip32_index_space() {
        let outcome = search_vanity_matches(
            &TEST_SEED,
            DerivationScheme::Bip32Secp256k1,
            u32::MAX,
            1,
            AttemptLimit::Bounded(1),
            1,
            &HashSet::new(),
            &match_any(),
            &ProgressBar::hidden(),
        )
        .expect("search");
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.attempts, 0);
        assert!(outcome.exhausted_indexes);
    }
}
