# Casper CLI Wallet

This CLI provides wallet management for Casper: create/recover wallets, derive accounts, and manage account names.

## Build and run

```bash
cargo build
cargo run -- wallet --help
```

## Storage layout

By default, wallets are stored under your OS config directory (for example, `~/Library/Application Support/casper-cli` on macOS). You can configure the secret storage backend in `config.toml`:

```bash
cargo run -- config edit
```

The layout under the base directory (file storage backend):

- `wallets/<name>.json` - wallet metadata (accounts, type, encryption flag)
- `secrets/<name>.enc` - encrypted wallet root secret

When using `storage.type = "keyring"`, secrets are stored in the OS keyring instead of the `secrets/` directory, the CLI does not prompt for a master password, and `--unencrypted` is not supported.

## Wallet commands

### wallet create

Creates a new wallet. BIP-39 is the default.

```bash
cargo run -- wallet create mywallet
```

Seeded (deterministic) wallets:

```bash
cargo run -- wallet create mywallet --seed "my-seed" --domain "my-domain"
```

Unencrypted (unsafe, for local dev only, file storage only):

```bash
cargo run -- wallet create mywallet --unencrypted
```

> [!NOTE]
> - If you want to migrate from Casper Wallet, use your saved mnemonic words and an empty, optional passphrase, then this tool can derive accounts from that.
> - If you want to derive accounts from a casper-devnet, pass `--seed <seed name>` (casper-devnet defaults to the `default` seed) and `--domain casper-unsafe-devnet-v1`. The devnet tool derives validator accounts from indexes 0..N and genesis accounts starting from index 100, so you may want `derive --start 100 --count <number of users>`.

### wallet recover

Recovers a wallet from a BIP-39 mnemonic. This will prompt for the mnemonic and optional passphrase.

```bash
cargo run -- wallet recover mywallet
```

### wallet list

Lists all wallets in the storage directory.

```bash
cargo run -- wallet list
```

### wallet info

Shows wallet type, encryption state, and known accounts.

```bash
cargo run -- wallet info mywallet
```

### wallet derive

Derives accounts from the wallet root and stores them in metadata. The command fails if the requested range overlaps existing accounts.

```bash
cargo run -- wallet derive mywallet --start 0 --count 3
```

To show private keys (dangerous):

```bash
cargo run -- wallet derive mywallet --show-private
```

### wallet add

Adds the next derived account. The account name is optional and defaults to `account-{index}`.

```bash
cargo run -- wallet add mywallet
cargo run -- wallet add mywallet alice
```

You can also use the external form:

```bash
cargo run -- wallet mywallet add
cargo run -- wallet mywallet add alice
```

### wallet rename-account

Renames an existing account in a wallet.

```bash
cargo run -- wallet rename-account mywallet old-name new-name
```

External form:

```bash
cargo run -- wallet mywallet rename-account old-name new-name
```

### wallet delete

Deletes the wallet metadata and secret.

```bash
cargo run -- wallet delete mywallet
```

## Network commands

Networks are stored in `config.toml` under the same config directory as wallets. If the file is missing, it is created with a default `devnet` entry:

```toml
active = "devnet"

[storage]
type = "file"
root_path = "/Users/you/Library/Application Support/casper-cli"

# Or use the OS keyring (service name is always "casper-cli")
# type = "keyring"

[networks.devnet]
chain_name = "casper-dev"
rest = "http://127.0.0.1:14102"
sse = "http://127.0.0.1:18102/events"
rpc = "http://127.0.0.1:11102/rpc"
```

### network use

Selects the active network by key or chain name:

```bash
cargo run -- network use devnet
cargo run -- network use casper-dev
```

### network list

Lists configured networks and highlights which one is active:

```bash
cargo run -- network list
```

## Balance command

Fetches the balance for a wallet account, account hash hex, or a raw public key hex. The active network is read from `config.toml`.

```bash
cargo run -- balance mywallet:account-0
cargo run -- balance 0202c1...deadbeef
cargo run -- balance <account-hash-hex>
```

## Config commands

### config edit

Opens `config.toml` in your `$EDITOR`:

```bash
cargo run -- config edit
```

## Transaction commands

### transaction put

Builds a session transaction from Wasm and submits it to the active network. The payment amount is specified in CSPR (default: 2.5 CSPR), with `--gas-price-tolerance` defaulting to 1. You can also use `tx` as an alias.

```bash
cargo run -- transaction put path/to/contract.wasm --payment-amount 2.5 --from mywallet:account-0
cargo run -- transaction put path/to/contract.wasm --from mywallet:account-0 --install-upgrade
```

## Security notes

Wallet secrets are encrypted at rest by default:

- Key derivation uses Argon2id (memory-hard) with ~64 MiB RAM, 3 iterations, and 1 lane for interactive CLI usage.
- Encryption uses XChaCha20-Poly1305 (AEAD) with a random 24-byte nonce per file.
- The wallet name is bound as AAD during encryption to prevent file-renaming attacks.
- Secret files are written atomically and locked down to restrictive permissions (0600 files, 0700 directories on Unix).

You can opt out of encryption with `--unencrypted` for local dev workflows when using file storage, but this stores secrets in plaintext.
