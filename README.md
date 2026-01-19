# Casper CLI Wallet

This CLI provides wallet management for Casper: create/recover wallets, derive accounts, and manage account names.

![Casper CLI demo](casper-cli.gif)

## Install

- `cargo install casper-cli`
- Or download a tarball from the [GitHub releases page](https://github.com/veles-labs/casper-cli/releases) and extract it into your `PATH`.

## Build and run

```bash
cargo build -p casper-cli
./target/debug/casper-cli wallet --help
```

Deriving accounts for use with a [casper-devnet](https://github.com/veles-labs/casper-devnet) instance:

```bash
casper-cli wallet create devnet --seed default --domain casper-unsafe-devnet-v1 --unencrypted
casper-cli wallet derive devnet --start 0 --count 4 --name 'validator-{index1}'
casper-cli wallet derive devnet --start 100 --count 4 --name 'user-{counter1}'
# Run the network in the background (-d switch)
docker run -d --rm -it \
  -p 11101:11101 -p 14101:14101 -p 18101:18101 -p 22101:22101 -p 28101:28101 \
  ghcr.io/veles-labs/casper-devnet
# Verify that the JSONRPC requests are working, and the derived paths are producing the same accounts.
casper-cli view-account user-1
```

## Development

Create a release tarball for the host platform:

```bash
cargo xtask package
```

The output is written to `dist/casper-cli-{version}-{target}.tar.gz`.

## Global options

- `--no-interactive` - Disable prompts when initializing `config.toml` (requires `--keyring` or `--file-storage` if the file is missing).
- `--keyring` - Force OS keyring storage for this run (overrides `config.toml`).
- `--file-storage <ROOT_PATH>` - Force file-based storage for this run using the provided root path (overrides `config.toml`).
- `--config-path <PATH>` - Use a custom `config.toml` path instead of the default projectdirs location.

## Storage layout

By default, wallets are stored under your OS config directory (for example, `~/Library/Application Support/casper-cli` on macOS). You can configure the secret storage backend in `config.toml`:

```bash
casper-cli config edit
```

The layout under the base directory (file storage backend):

- `wallets/<name>.json` - wallet metadata (accounts, type, encryption flag)
- `secrets/<name>.enc` - encrypted wallet root secret

When using `storage.type = "keyring"`, secrets are stored in the OS keyring instead of the `secrets/` directory, the CLI does not prompt for a master password, and `--unencrypted` is not supported.

## Wallet commands

### wallet create

Creates a new wallet. BIP-39 is the default.

```bash
casper-cli wallet create mywallet
```

Derivation scheme (default is BIP-32 secp256k1):

```bash
casper-cli wallet create mywallet --bip32
casper-cli wallet create mywallet --slip10
```

Mnemonic word count (12, 15, 18, 21, 24; default 24):

```bash
casper-cli wallet create mywallet --words 12
casper-cli wallet create mywallet --slip10 --words 24
casper-cli wallet create mywallet --words 21
```

Seeded (deterministic) wallets:

```bash
casper-cli wallet create mywallet --seed "my-seed" --domain "my-domain"
```

Unencrypted (unsafe, for local dev only, file storage only):

```bash
casper-cli wallet create mywallet --unencrypted
```

> [!NOTE]
> - If you want to migrate from Casper Wallet, use your saved mnemonic words and an empty, optional passphrase, then this tool can derive accounts from that.
> - If you want to derive accounts from a casper-devnet, pass `--seed <seed name>` (casper-devnet defaults to the `default` seed) and `--domain casper-unsafe-devnet-v1`. The devnet tool derives validator accounts from indexes 0..N and genesis accounts starting from index 100, so you may want `derive --start 100 --count <number of users>`.

### wallet recover

Recovers a wallet from a BIP-39 mnemonic. This will prompt for the mnemonic and optional passphrase.

```bash
casper-cli wallet recover mywallet
```

Derivation scheme (default is BIP-32 secp256k1):

```bash
casper-cli wallet recover mywallet --bip32
casper-cli wallet recover mywallet --slip10
```

### wallet import-legacy

Imports a legacy secret key PEM into a wallet. Legacy wallets do not support derivation or accounts.

```bash
casper-cli wallet import-legacy mywallet --pem-file /path/to/secret_key.pem
```

Stdin form:

```bash
cat /path/to/secret_key.pem | casper-cli wallet import-legacy mywallet
```

### wallet list

Lists all wallets in the storage directory.

```bash
casper-cli wallet list
```

### wallet info

Shows wallet type, encryption state, known accounts, and their balances on the active network (missing accounts show `0 CSPR`). Legacy wallets show their origin, key type, and public key.

```bash
casper-cli wallet info mywallet
```

### wallet derive

Derives accounts from the wallet root and stores them in metadata. The command fails if the requested range overlaps existing accounts. Use `--name` with a `tinytemplate` template to control account names; the DeriveNameContext fields are `index` (0-based), `index1` (1-based), `wallet` (wallet name), `network` (active network key), and `chain_name` (active network chain name). The default is `account-{index}`.

Default derivation paths:

- BIP-32 secp256k1: `m/44'/506'/0'/0/{index}`
- SLIP-0010 ed25519 (hardened only): `m/44'/506'/0'/0'/{index}'`

```bash
casper-cli wallet derive mywallet --start 0 --count 3
```

Custom name templates:

```bash
casper-cli wallet derive mywallet --count 2 --name "{wallet}-{network}-{index1}"
casper-cli wallet derive mywallet --count 2 --name "{chain_name}-account-{index}"
casper-cli wallet derive devnet --start 0 --count 4 --name "validator-{index1}"
casper-cli wallet derive devnet --start 100 --count 4 --name "user-{index1}"
```

To show private keys (dangerous, hex-encoded Casper secret key bytes with tag prefix):

```bash
casper-cli wallet derive mywallet --show-private
```

### wallet rename-account

Renames an existing account in a wallet.

```bash
casper-cli wallet rename-account mywallet old-name new-name
```

External form:

```bash
casper-cli wallet mywallet rename-account old-name new-name
```

### wallet delete

Deletes the wallet metadata and secret.

```bash
casper-cli wallet delete mywallet
```

## Network commands

Networks are stored in `config.toml` under the same config directory as wallets. If the file is missing, `casper-cli` will prompt for the storage backend and then create it with a default `devnet` entry:

```toml
active = "devnet"

[storage]
type = "keyring"

# For file-based storage:
# type = "file"
# root_path = "/Users/you/Library/Application Support/casper-cli"

[networks.devnet]
chain_name = "casper-dev"
rest = "http://127.0.0.1:14102"
sse = "http://127.0.0.1:18102/events"
rpc = "http://127.0.0.1:11102/rpc"
# binary_port supports address:port, tcp://address:port, ws://address[:port]/path, or wss://address[:port]/path.
# ws defaults to port 80 and wss defaults to port 443 if omitted.
# wss uses system trust roots and will fail on invalid certificates.
binary_port = "127.0.0.1:28101"
```

### network use

Selects the active network by key or chain name:

```bash
casper-cli network use devnet
casper-cli network use casper-dev
```

### network list

Lists configured networks and highlights which one is active:

```bash
casper-cli network list
```

## Balance command

Fetches the balance for a wallet account, legacy wallet name, account hash hex, or a raw public key hex. The active network is read from `config.toml`.

```bash
casper-cli balance mywallet:account-0
casper-cli balance legacywallet
casper-cli balance 0202c1...deadbeef
casper-cli balance <account-hash-hex>
```

## View account command

Fetches account details from the active network and prints named keys for a wallet account, legacy wallet name, or raw identifier.

```bash
casper-cli view-account mywallet:account-0
casper-cli view-account legacywallet
casper-cli view-account <public-key-hex>
casper-cli view-account <account-hash-hex>
```

## Config commands

### config edit

Opens `config.toml` in your `$EDITOR`:

```bash
casper-cli config edit
```

## Transaction commands

Simulation uses the network binary port; set `binary_port` (`address:port`, `tcp://address:port`, `ws://address[:port]/path`, or `wss://address[:port]/path`) in `config.toml` before using `--simulate`.
Wallet references use `wallet:account`; legacy wallets can be referenced by wallet name alone.
The simulator runs a local execution engine and will download trie objects from the node via the
binary port as needed. Unlike speculative execution, it can report return values, which can be
useful for calls like `balance_of` on a CEP-18 token without reconstructing dictionary item keys
from base64.
Return values are rendered on a best-effort basis into a human-readable CLValue representation,
even for nested/complex types. If formatting fails, the raw `0x` bytes are shown instead.

Examples (from unit tests):

| CLType | Return bytes (hex) | Rendered output |
| --- | --- | --- |
| `Option<Bool>` | `0x0101` | `Some(true)` |
| `(Bool, U32, String)` | `0x0107000000020000006869` | `(true, 7, hi)` |
| `Map<String, U32>` | `0x0200000005000000616c70686101000000040000006265746102000000` | `{alpha: 1, beta: 2}` |

```bash
casper-cli transaction call --simulate --from devnet:user-1 $CONTRACT_HASH hello
```

Example output:

```
Simulation result on devnet at block height 10964:
Gas used: 0.013064020
Execution succeeded.
Return String: "Hello, world!"
New tries downloaded: 1
Cache hits during execution: 25
Cleaning up unreferenced tries...
Cleaned up 2 unreferenced tries
```

### transaction put

Builds a session transaction from Wasm and submits it to the active network. The payment amount is specified in CSPR (default: 2.5 CSPR), with `--gas-price-tolerance` defaulting to 1. Use `--simulate` to run a local execution engine via the binary port without submitting the transaction. You can also use `tx` as an alias.

```bash
casper-cli transaction put path/to/contract.wasm --payment-amount 2.5 --from mywallet:account-0
casper-cli transaction put path/to/contract.wasm --from mywallet:account-0 --install-upgrade
casper-cli transaction put path/to/contract.wasm --from mywallet:account-0 \
  --arg flag:Bool=true --arg amount:U512=1000000000000
casper-cli transaction put path/to/contract.wasm --from mywallet:account-0 --simulate
casper-cli transaction put path/to/contract.wasm --from mywallet:account-0 --raw
```

### transaction call

Calls a stored contract by hash (formatted `contract-`/`addressable-entity-` or raw hex) using the `call` entry point. To call by name, pass the named key alias directly. Use `--package` to interpret the target as a package hash (latest version by default) and `--version` with `--package` to select a specific package version. The payment amount is specified in CSPR (default: 2.5 CSPR), with `--gas-price-tolerance` defaulting to 1. Use `--simulate` to run a local execution engine via the binary port without submitting the transaction.

```bash
casper-cli transaction call contract-... entry_point --from mywallet:account-0
casper-cli tx call <contract-hash-hex> entry_point --payment-amount 3.0 --gas-price-tolerance 2 --from mywallet:account-0
casper-cli transaction call contract-... entry_point --from mywallet:account-0 \
  --arg recipient:Key=hash-... --arg note:String="hello"
casper-cli tx call my_contract entry_point --from mywallet:account-0
casper-cli tx call package-... entry_point --package --from mywallet:account-0
casper-cli tx call my_package entry_point --package --version 3 --from mywallet:account-0
casper-cli tx call <contract-hash-hex> entry_point --from mywallet:account-0 --simulate
casper-cli tx call <contract-hash-hex> entry_point --from mywallet:account-0 --raw
```

### transaction get

Fetches execution details for a transaction by hash. Use `--finalized-approvals` to request finalized approvals and `--raw` to print only the execution info JSON (or `null` if missing).

```bash
casper-cli tx get <transaction-hash-hex>
casper-cli tx get <transaction-hash-hex> --finalized-approvals
casper-cli tx get deploy-hash-<hex> --raw
```

### transaction transfer

Transfers CSPR from a wallet account to a target account. The recipient can be a wallet/account reference, public key bytes hex, or account hash bytes hex. You can set `--gas-price-tolerance` (default: 1). Use `--simulate` to run a local execution engine via the binary port without submitting the transaction, or `--raw` to print only the transaction hash.

```bash
casper-cli tx transfer --from mywallet:account-0 --to mywallet:account-1 --amount 1.25
casper-cli tx transfer --from mywallet:account-0 --to <public-key-hex> --amount 10
casper-cli tx transfer --from mywallet:account-0 --to <account-hash-hex> --amount 0.5 --gas-price-tolerance 2
casper-cli tx transfer --from mywallet:account-0 --to mywallet:account-1 --amount 1.25 --simulate
casper-cli tx transfer --from mywallet:account-0 --to mywallet:account-1 --amount 1.25 --raw
```

### Argument format

You can pass multiple `--arg` values. Each arg has one of two forms:

- `name:cltype=value` to parse the value using full CLType syntax (arbitrarily nested).
- `name=value` to pass raw hex bytes with implicit `Any` type (optional `0x` prefix).

If the arg name contains `:` or `=`, escape them with backslashes (e.g. `meta\\:x\\=y`).

The `cltype` portion supports arbitrarily nested Rust-like syntax (e.g. `Result<Option<U64>, String>`).
Aliases are also accepted: `account_hash`/`account-hash` => `ByteArray[32]`, `byte_array`/`byte-array`
=> `ByteArray[...]`, `public_key`/`public-key` => `PublicKey`, `()` => `Unit`.

For `Option<T>` where `T` is a basic type (Bool, numeric primitives, String, Key, URef, PublicKey, Unit),
you can supply the human-readable value for `Some(T)` and the literal `None` for the none tag. To force
hex bytes for `Option<T>`, prefix the value with `0x`.

Examples:

| --arg example | CLType | value bytes (hex) |
| --- | --- | --- |
| `--arg flag:Bool=true` | `CLType::Bool` | `01` |
| `--arg opt:Option<Bool>=None` | `CLType::Option(CLType::Bool)` | `00` |
| `--arg opt:Option<String>=hello` | `CLType::Option(CLType::String)` | `010500000068656c6c6f` |
| `--arg opt:Option<Bool>=0x0101` | `CLType::Option(CLType::Bool)` | `0101` |
| `--arg msg:String=abc` | `CLType::String` | `03000000616263` |
| `--arg amount:U64=1234` | `CLType::U64` | `d204000000000000` |
| `--arg bytes:List<U8>=0x03000000010203` | `CLType::List(CLType::U8)` | `03000000010203` |
| `--arg res:Result<Option<U64>, U64>=0x01010700000000000000` | `CLType::Result { ok, err }` | `01010700000000000000` |
| `--arg map:Map<String, U32>=0x0200000005000000616c70686101000000040000006265746102000000` | `CLType::Map { key, value }` | `0200000005000000616c70686101000000040000006265746102000000` |
| `--arg pair:(Bool, U32)=0x0102000000` | `CLType::Tuple2([Bool, U32])` | `0102000000` |
| `--arg data:ByteArray[4]=0x01020304` | `CLType::ByteArray(4)` | `01020304` |
| `--arg acct:account_hash=0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` | `CLType::ByteArray(32)` | `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` |
| `--arg payload=0xdeadbeef` | `CLType::Any` | `deadbeef` |

Arguments:

- `--arg name:cltype=value` to pass a typed argument (CLType syntax supports nesting like `Option<Bool>` or `Result<U64, U64>`).
- `--arg name=value` to pass raw bytes as hex with implicit `Any` type (optional `0x` prefix).

## Security notes

Wallet secrets are encrypted at rest by default:

- Key derivation uses Argon2id (memory-hard) with ~64 MiB RAM, 3 iterations, and 1 lane for interactive CLI usage.
- Encryption uses XChaCha20-Poly1305 (AEAD) with a random 24-byte nonce per file.
- The wallet name is bound as AAD during encryption to prevent file-renaming attacks.
- Secret files are written atomically and locked down to restrictive permissions (0600 files, 0700 directories on Unix).

You can opt out of encryption with `--unencrypted` for local dev workflows when using file storage, but this stores secrets in plaintext.

## License

Apache-2.0
