# WWChain

[![CI](https://github.com/OWNER/wwchain/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/wwchain/actions/workflows/ci.yml)

WWChain is a minimal blockchain prototype written in Rust. Each node maintains its own chain, shares blocks and transactions over TCP and keeps a simple list of peers. The project exists mostly for learning and experimentation.

## Building

```bash
cargo build
```

This compiles the project and fetches all needed dependencies.

## Running a node

Launch a node with optional arguments:

```bash
cargo run -- --port <PORT> --node-name <NAME> --peers <PEER1,PEER2,...> --chain-dir <DIR>
```

When the `tls` feature is enabled you can also provide certificate paths:

```bash
cargo run --features tls -- --tls-cert cert.pem --tls-key key.pem
```

Self-signed certificates for development can be generated with:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
```

- `--port` - TCP port to listen on (default: 6001).
- `--node-name` - friendly name used in prompts (default: "node1").
- `--peers` - comma separated list of peer addresses to connect to at startup.
- `--chain-dir` - directory where the blockchain database is stored (default: `chain_db`).

Example starting a single node:

```bash
cargo run -- --port 6001 --node-name node1
```

## Starting multiple nodes locally

Open separate terminals and run each node on a different port while listing the other node as a peer. For example:

Terminal 1:

```bash
cargo run -- --port 6001 --node-name node1 --peers 127.0.0.1:6002
```

Terminal 2:

```bash
cargo run -- --port 6002 --node-name node2 --peers 127.0.0.1:6001
```

Each node will print received messages and you can send transactions via the interactive prompt.
The prompt also accepts a few commands like `add`, `remove`, `list` and `balance`.
Use `balance` at any time to print your wallet's current balance.

### Wallet encryption

Set the `WALLET_PASSWORD` environment variable before starting a node to
encrypt the wallet's private key. The file will then be written with an
`enc:` prefix and must be decrypted using the same password on the next
run. Without the variable the key is stored as plain hex for backward
compatibility.

## Chain persistence

Blocks are now stored in a [RocksDB](https://crates.io/crates/rocksdb) database. The database lives in a directory (default `chain_db`) which can be changed with the `--chain-dir` argument. Each block is written atomically so crashes cannot corrupt previously committed data.

## Logging

Output is now produced using the [`tracing`](https://crates.io/crates/tracing) framework. Set the `RUST_LOG` environment variable to control log verbosity, e.g. `RUST_LOG=info`.

## Optional dependencies

`Cargo.toml` includes commented dependencies for potential future features:

- `color-backtrace` and `anyhow` for richer error output.
- `rand` and `secp256k1` for wallet/crypto functionality.
- `tiny-http` to expose a REST API.
- `cargo-watch` to rebuild automatically during development.

Uncomment them in `Cargo.toml` when needed.


## Setup for tests and documentation

Run the helper script to ensure all crates are fetched, tests pass and docs are built:

```bash
./setup.sh
```

The script installs Rust with `rustup` if necessary, fetches dependencies,
formats the code with `cargo fmt --all`, runs `cargo test` and generates
documentation with `cargo doc`.

## Security/Disclaimer

This prototype is for learning and experimentation only. It has not been audited or hardened and should **not** be used to manage real cryptocurrency or any sensitive data.
The cryptographic primitives are provided by the well-vetted
[`sha2`](https://crates.io/crates/sha2) and
[`secp256k1`](https://crates.io/crates/secp256k1) crates, but the overall
application has not been formally reviewed.

## License

This project is licensed under the [MIT License](LICENSE).
