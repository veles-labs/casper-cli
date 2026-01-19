use anyhow::{Result, anyhow, bail};
use slip10_ed25519::derive_ed25519_private_key;

pub const DEFAULT_SLIP0010_ED25519_PATH_PREFIX: &str = "m/44'/506'/0'/0'";

pub fn default_path(index: u32) -> String {
    format!("{}/{}'", DEFAULT_SLIP0010_ED25519_PATH_PREFIX, index)
}

pub fn parse_hardened_path(path: &str) -> Result<Vec<u32>> {
    let mut segments = path.split('/');
    let Some(root) = segments.next() else {
        bail!("slip0010 path cannot be empty");
    };
    if root != "m" {
        bail!("slip0010 path must start with 'm'");
    }

    let mut indexes = Vec::new();
    for segment in segments {
        if segment.is_empty() {
            bail!("slip0010 path segment cannot be empty");
        }
        let Some(value) = segment.strip_suffix('\'') else {
            bail!("slip0010 paths must use hardened segments like 0'");
        };
        if value.is_empty() {
            bail!("slip0010 path segment cannot be empty");
        }
        let index = value
            .parse::<u32>()
            .map_err(|_| anyhow!("slip0010 path segment is not a number: {value}"))?;
        indexes.push(index);
    }

    if indexes.is_empty() {
        bail!("slip0010 path must include at least one hardened segment");
    }

    Ok(indexes)
}

pub fn derive_private_key(seed: &[u8], path: &[u32]) -> Result<[u8; 32]> {
    if path.is_empty() {
        bail!("slip0010 path must include at least one hardened segment");
    }
    Ok(derive_ed25519_private_key(seed, path))
}

#[cfg(test)]
mod tests {
    use super::parse_hardened_path;

    #[test]
    fn parse_valid_hardened_path() {
        let path = "m/44'/506'/0'/0'/5'";
        let parsed = parse_hardened_path(path).expect("parse");
        assert_eq!(parsed, vec![44, 506, 0, 0, 5]);
    }

    #[test]
    fn reject_non_hardened_path() {
        let err = parse_hardened_path("m/44/0'").expect_err("should fail");
        assert!(
            err.to_string()
                .contains("slip0010 paths must use hardened segments")
        );
    }
}
