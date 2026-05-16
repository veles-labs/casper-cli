# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added `wallet derive-vanity` for parallel vanity account derivation scans.
### Changed
- Transaction submission now uses the `--from` key's account hash as the default `initiator_addr`
  for transfers and Wasm/contract calls.
### Deprecated
### Removed
### Fixed
### Security

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
