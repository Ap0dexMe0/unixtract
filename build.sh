#!/usr/bin/env bash
#
# Cross-compile unixtract for multiple targets and collect the binaries into
# ./dist. Run from the repository root:
#
#   ./build.sh                # build the default target set
#   ./build.sh <target> ...   # build only the given rustc target triples
#
# Requirements (Debian/Ubuntu example):
#   rustup                                     # toolchain manager
#   sudo apt install gcc-mingw-w64-x86-64      # for x86_64-pc-windows-gnu
#   sudo apt install gcc-aarch64-linux-gnu     # for aarch64-unknown-linux-gnu (optional)
#
set -euo pipefail

# --- Target set ------------------------------------------------------------
# Override by passing target triples as arguments.
DEFAULT_TARGETS=(
    x86_64-unknown-linux-gnu
    x86_64-pc-windows-gnu
)

if [ "$#" -gt 0 ]; then
    TARGETS=("$@")
else
    TARGETS=("${DEFAULT_TARGETS[@]}")
fi

BIN_NAME="unixtract"
DIST_DIR="dist"

echo "==> Building ${BIN_NAME} for: ${TARGETS[*]}"

mkdir -p "$DIST_DIR"

for target in "${TARGETS[@]}"; do
    echo
    echo "==> Target: $target"

    # Ensure the target's std library is installed.
    if ! rustup target list --installed | grep -qx "$target"; then
        echo "    Installing rust std for $target ..."
        rustup target add "$target"
    fi

    cargo build --release --target "$target"

    # Work out the produced binary name (Windows targets get a .exe suffix).
    case "$target" in
        *windows*) src="target/$target/release/${BIN_NAME}.exe" ;;
        *)         src="target/$target/release/${BIN_NAME}" ;;
    esac

    if [ ! -f "$src" ]; then
        echo "    !! Expected binary not found: $src" >&2
        exit 1
    fi

    # Friendly output name, e.g. unixtract-x86_64-pc-windows-gnu.exe
    case "$target" in
        *windows*) dst="$DIST_DIR/${BIN_NAME}-${target}.exe" ;;
        *)         dst="$DIST_DIR/${BIN_NAME}-${target}" ;;
    esac

    cp "$src" "$dst"
    echo "    -> $dst"
done

echo
echo "==> Done. Binaries are in ./${DIST_DIR}"
ls -la "$DIST_DIR"
