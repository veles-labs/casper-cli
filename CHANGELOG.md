# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added `transaction call --simulate --initiator <account-hash>` for unsigned local getter calls without a wallet or secret key.
- Added structured JSON results for `--simulate --raw`, including typed return values,
  execution errors, gas consumption and state-query statistics.
- Added `wallet password <name>` to set or change password protection for file-backed wallets, with `--unencrypted` to remove it explicitly.
- Added `wallet derive-vanity` for parallel vanity account derivation scans.
- Added `--speculative` to transaction put, call, and transfer commands for node-side `speculative_exec_txn` preflight without submission.
### Changed
- Pinned the development toolchain to Rust 1.99.1.
- Transaction submission now uses the `--from` key's account hash as the default `initiator_addr`
  for transfers and Wasm/contract calls.
- Local transaction simulation now queries state by key over JSON-RPC and verifies and caches Merkle proofs at the selected state root, without requiring binary-port trie access. Operations using `keys_with_prefix` fail explicitly because key enumeration is disabled.
### Deprecated
### Removed
### Fixed
- Contract calls with `--package` now recognize `contract-package-` hashes instead of
  treating them as named key aliases, including during local simulation.
- Local simulation no longer invokes macOS system-proxy or trust-service discovery for RPC
  requests, avoiding `SystemConfiguration` and certificate-verification failures in headless
  processes while retaining TLS verification with bundled public roots.
### Security
- Wallet secret replacements now use unique temporary files with restrictive permissions before writing, and password/decrypted plaintext buffers are zeroized on drop.

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

[Unreleased]: https://github.com/veles-labs/casper-cli/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/veles-labs/casper-cli/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/veles-labs/casper-cli/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/veles-labs/casper-cli/releases/tag/v0.2.1
