#!/usr/bin/env bash
set -euo pipefail

echo "Building unixtract (Linux + Windows)..."

# Clean first
cargo clean

# Build Linux
cargo build --target x86_64-unknown-linux-gnu --release

# Build Windows (GNU)
cargo build --target x86_64-pc-windows-gnu --release

# Prepare dist folder
mkdir -p dist

echo "Collecting binaries..."

# Linux binary
LINUX_BIN="target/x86_64-unknown-linux-gnu/release/unixtract"
if [ -f "$LINUX_BIN" ]; then
    cp "$LINUX_BIN" "dist/unixtract-linux"
fi

# Windows binary
WINDOWS_BIN="target/x86_64-pc-windows-gnu/release/unixtract.exe"
if [ -f "$WINDOWS_BIN" ]; then
    cp "$WINDOWS_BIN" "dist/unixtract-windows.exe"
fi

echo "Cleaning target directory..."
rm -rf target

echo "Done. Binaries are in ./dist"