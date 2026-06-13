#!/usr/bin/env bash
# Fetch the pandoc binary for the current host and place it where Tauri expects
# its sidecar: src-tauri/binaries/pandoc-<rust-target-triple>(.exe).
#
# Run before `pnpm tauri build` / `pnpm tauri dev` (CI does this per-OS). The
# binaries/ dir is gitignored — pandoc is NOT committed (it's ~150 MB).
#
# Override the version with PANDOC_VERSION=x.y. Requires: rustc, curl, tar
# (bsdtar on macOS/Windows extracts .zip too).
set -euo pipefail

PANDOC_VERSION="${PANDOC_VERSION:-3.10}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../src-tauri/binaries"
TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
mkdir -p "$OUT_DIR"

base="https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$TRIPLE" in
  x86_64-unknown-linux-gnu)  asset="pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz"; inner="bin/pandoc"; out="pandoc-$TRIPLE" ;;
  aarch64-unknown-linux-gnu) asset="pandoc-${PANDOC_VERSION}-linux-arm64.tar.gz"; inner="bin/pandoc"; out="pandoc-$TRIPLE" ;;
  x86_64-apple-darwin)       asset="pandoc-${PANDOC_VERSION}-x86_64-macOS.zip";   inner="bin/pandoc"; out="pandoc-$TRIPLE" ;;
  aarch64-apple-darwin)      asset="pandoc-${PANDOC_VERSION}-arm64-macOS.zip";    inner="bin/pandoc"; out="pandoc-$TRIPLE" ;;
  x86_64-pc-windows-msvc)    asset="pandoc-${PANDOC_VERSION}-windows-x86_64.zip"; inner="pandoc.exe"; out="pandoc-$TRIPLE.exe" ;;
  *) echo "Unsupported target triple: $TRIPLE" >&2; exit 1 ;;
esac

curl -fsSL "$base/$asset" -o "$tmp/pandoc-archive"
tar -xf "$tmp/pandoc-archive" -C "$tmp"
cp "$tmp"/pandoc-*/"$inner" "$OUT_DIR/$out"
[ "${out##*.}" = "exe" ] || chmod +x "$OUT_DIR/$out"
echo "pandoc $PANDOC_VERSION -> $OUT_DIR/$out"
