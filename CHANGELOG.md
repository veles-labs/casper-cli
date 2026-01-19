# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added balance display for wallets.
- Added support for importing legacy PEM secret keys as wallets.
- Added SLIP-0010 ed25519 wallet derivation via `--slip10`.
### Changed
- `wallet derive --show-private` now outputs hex-encoded Casper secret key bytes with tag prefix.
### Deprecated
### Removed
### Fixed
### Security

## [0.2.1] - 2026-01-15
### Added
- Initial release.

[Unreleased]: https://github.com/veles-labs/casper-cli/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/veles-labs/casper-cli/releases/tag/v0.2.1
