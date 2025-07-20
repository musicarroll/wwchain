# WWChain

WWChain is a minimal blockchain prototype written in Rust. Each node maintains its own chain, shares blocks and transactions over TCP and keeps a simple list of peers. The project exists mostly for learning and experimentation.

## Building

```bash
cargo build
```

This compiles the project and fetches all needed dependencies.

## Running a node

Launch a node with optional arguments:

```bash
cargo run -- --port <PORT> --node-name <NAME> --peers <PEER1,PEER2,...>
```

- `--port` - TCP port to listen on (default: 6001).
- `--node-name` - friendly name used in prompts (default: "node1").
- `--peers` - comma separated list of peer addresses to connect to at startup.

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

The script installs Rust with `rustup` if necessary, fetches dependencies, runs `cargo test` and generates documentation with `cargo doc`.

## License

This project is licensed under the [MIT License](LICENSE).
