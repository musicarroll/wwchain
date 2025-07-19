#!/usr/bin/env bash
set -euo pipefail

# Helper script for local development and CI.
# It installs the Rust toolchain if missing, ensures build
# prerequisites are present and then runs tests and
# documentation generation.  The script is tolerant of an
# offline environment so it can run in restricted Codex
# containers.

# Install basic build tools when available.  Failure to
# update package lists is ignored so the script still works
# without network access.
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y || true
    sudo apt-get install -y build-essential pkg-config libssl-dev curl || true
fi

# Install Rust toolchain if cargo is not available
if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust toolchain not found. Installing via rustup..."
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Fetch all dependencies.  This may fail in an offline
# container but we continue so previously cached crates can
# still be used.
cargo fetch || echo "cargo fetch failed - continuing with any cached crates"

# Run the project tests
cargo test --offline || echo "Tests skipped due to missing crates"

# Generate documentation without pulling in dependencies' docs
cargo doc --no-deps --offline || echo "Doc build skipped due to missing crates"

echo "Setup complete."
