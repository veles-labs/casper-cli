# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.5.0] - 2026-10-29

### Added

- `wallet derive-vanity` searches derivation paths in parallel using prefix, suffix,
  and regular-expression filters over account hashes or public keys. Supports
  configurable worker counts, bounded or unbounded searches, and account name templates.
- `wallet password <name>` sets or changes file-backed wallet encryption without
  changing wallet keys, derived accounts, or the BIP-39 passphrase. Supports mnemonic,
  seeded, and imported PEM wallets; `--unencrypted` explicitly removes protection.
  New passwords for this command must be nonempty; OS keyring wallets are unsupported.
- `--speculative` on `transaction put`, `call`, and `transfer` previews signed
  transactions through the RPC `speculative_exec_txn` method without submission.
  Supports `--raw` JSON output and exits nonzero on execution failure. Cannot be
  combined with `--simulate`.
- `--simulate --raw` on transaction commands emits a versioned JSON result with
  typed return values, execution errors, block and state-root information, gas
  consumption, and state-query/cache statistics. Execution failures emit their
  result before exiting nonzero.
- `transaction call --simulate --initiator <account-hash>` runs unsigned local
  contract calls without accessing a wallet or secret key. Requires `--simulate`
  and cannot be combined with `--from` or `--speculative`.

### Changed

- Default mainnet and testnet RPC/SSE endpoints now use `node.mainnet.casper.network`
  and `node.testnet.casper.network`. New config entries for these networks omit the
  unused `rest` and `binary_port` fields.
- Network config fields `rest` and `binary_port` are optional and accept empty values.
  Network selection and listing handle entries that omit them.
- Local simulation fetches state by key through the active RPC endpoint's
  `query_global_state` method, replacing binary-port trie downloads. Verified state
  proofs are cached per state root; cache statistics now count state queries and
  values from other roots are pruned. Binary-port access is no longer required.
- Transaction V1 transfers, Wasm submissions, and stored contract calls use the
  `--from` key's account hash as `initiator_addr` while still signing with that key.
- Pinned the development toolchain to Rust 1.99.1.
- Release tag pushes now publish the crate to crates.io after all platform builds
  succeed, as well as attaching binaries to the GitHub release.

### Deprecated

### Removed

- Key-prefix enumeration (`keys_with_prefix`) in local simulation. Contracts that
  require prefix scans now fail explicitly with the RPC state-query backend.

### Fixed

- `transaction call --package` recognizes `contract-package-` hashes instead of
  treating them as named key aliases, including during local simulation. Malformed
  package hashes produce parsing errors.
- Local simulation supports debug Wasm importing `casper_print`. Contract prints
  go to stderr so `--raw` stdout remains a single JSON result.
- Simulation state-access failures abort execution and report their cause instead
  of being treated as missing state.
- Local simulation avoids macOS system-proxy and trust-service discovery for RPC
  requests, fixing `SystemConfiguration` and certificate-verification failures in
  headless processes while retaining TLS verification with bundled public roots.

### Security

- File-backed wallet secret replacements use unique temporary files and atomic
  writes, with `0600` permissions applied before writing on Unix. This prevents
  writes through predictable temporary-file symlinks and exposure before chmod.
- Password, confirmation, and decrypted plaintext buffers are zeroized on drop.
- Password changes authenticate the current encrypted wallet before rewriting,
  serialize concurrent password changes with a wallet lock, and attempt to restore
  the original secret if updating wallet metadata fails. Rollback failures are reported.
- Local simulation verifies fetched and cached Merkle proofs against the requested
  key and selected state root, rejecting corrupt or mismatched data. Missing-key
  responses still rely on the RPC node because the query API provides no absence proofs.

## [0.4.0] - 2026-01-22
### Added
### Changed
- `config edit` now falls back to `vim`, then `nano` when `$EDITOR` is unset.
- Default config now includes `mainnet` and `testnet` endpoints and defaults the active network to `testnet`.
### Deprecated
### Removed
### Fixed
### Security

## [0.3.0] - 2026-01-19
### Added
- Added balance display for wallets.
- Added support for importing legacy PEM secret keys as wallets.
- Added SLIP-0010 ed25519 wallet derivation via `--slip10`.
- Added `--words 12|15|18|21|24` for BIP-39 mnemonic generation.
### Changed
- `wallet derive --show-private` now outputs hex-encoded Casper secret key bytes with tag prefix.
- Renamed `view-account` to `account view`.
- Moved `balance` to `account balance`.
- Wallet account listings now display account hashes instead of public key hex.
- `account view` now shows the public key and key type when available.
### Deprecated
### Removed
### Fixed
### Security

## [0.2.1] - 2026-01-15
### Added
- Initial release.

[Unreleased]: https://github.com/veles-labs/casper-cli/compare/0.5.0...HEAD
[0.5.0]: https://github.com/veles-labs/casper-cli/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/veles-labs/casper-cli/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/veles-labs/casper-cli/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/veles-labs/casper-cli/releases/tag/0.2.1
