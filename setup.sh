#!/usr/bin/env bash
set -e

# Setup script to fetch dependencies, run tests, and build documentation

# Install Rust toolchain if cargo is not available
if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust toolchain not found. Installing via rustup..."
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Fetch all dependencies to ensure crates are available offline
cargo fetch

# Run the project tests
cargo test

# Generate documentation without pulling in dependencies' docs
cargo doc --no-deps

echo "Setup complete."
