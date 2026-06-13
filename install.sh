#!/bin/sh
# pwn2report installer for Linux & macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/own2pwn-fr/pwn2report/main/install.sh | sh
#
# Downloads the matching asset from the latest GitHub Release (or the tag in
# PWN2REPORT_VERSION) and installs it. Linux → AppImage in ~/.local/bin;
# macOS → app in /Applications. Only `curl` is required.
set -eu

REPO="own2pwn-fr/pwn2report"
BIN="pwn2report"

err() { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$1"; }

command -v curl >/dev/null 2>&1 || err "curl is required"

OS="$(uname -s)"
ARCH="$(uname -m)"

# Resolve the release JSON (latest, or a specific tag via PWN2REPORT_VERSION).
if [ -n "${PWN2REPORT_VERSION:-}" ]; then
  API="https://api.github.com/repos/$REPO/releases/tags/$PWN2REPORT_VERSION"
else
  API="https://api.github.com/repos/$REPO/releases/latest"
fi
info "Resolving release…"
JSON="$(curl -fsSL "$API")" || err "could not reach the GitHub release API"

# Pick the first asset download URL whose filename contains $1.
asset_url() {
  printf '%s' "$JSON" \
    | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"(https[^"]+)"/\1/' \
    | grep -iE "$1" \
    | head -n1
}

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) PAT='amd64\.AppImage$|x86_64\.AppImage$' ;;
      aarch64|arm64) PAT='aarch64\.AppImage$|arm64\.AppImage$' ;;
      *) err "unsupported Linux arch: $ARCH" ;;
    esac
    URL="$(asset_url "$PAT")"
    [ -n "$URL" ] || err "no AppImage asset found for $ARCH in this release"
    DEST_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
    mkdir -p "$DEST_DIR"
    DEST="$DEST_DIR/$BIN"
    info "Downloading $(basename "$URL")…"
    curl -fSL --progress-bar "$URL" -o "$DEST"
    chmod +x "$DEST"
    info "Installed to $DEST"
    case ":$PATH:" in
      *":$DEST_DIR:"*) : ;;
      *) printf '\033[33mnote:\033[0m add %s to your PATH (e.g. echo '\''export PATH="%s:$PATH"'\'' >> ~/.profile)\n' "$DEST_DIR" "$DEST_DIR" ;;
    esac
    info "Run it with: $BIN"
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) PAT='aarch64\.dmg$|arm64\.dmg$' ;;
      x86_64) PAT='x64\.dmg$|x86_64\.dmg$' ;;
      *) err "unsupported macOS arch: $ARCH" ;;
    esac
    URL="$(asset_url "$PAT")"
    [ -n "$URL" ] || err "no .dmg asset found for $ARCH in this release"
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    info "Downloading $(basename "$URL")…"
    curl -fSL --progress-bar "$URL" -o "$TMP/p.dmg"
    VOL="$(hdiutil attach "$TMP/p.dmg" -nobrowse -readonly | grep -o '/Volumes/.*' | head -n1)"
    [ -n "$VOL" ] || err "could not mount the disk image"
    APP="$(find "$VOL" -maxdepth 1 -name '*.app' | head -n1)"
    [ -n "$APP" ] || { hdiutil detach "$VOL" >/dev/null 2>&1; err "no .app inside the dmg"; }
    info "Installing to /Applications…"
    rm -rf "/Applications/$(basename "$APP")"
    cp -R "$APP" /Applications/
    hdiutil detach "$VOL" >/dev/null 2>&1 || true
    # Unsigned build: clear the quarantine flag so Gatekeeper doesn't block it.
    xattr -dr com.apple.quarantine "/Applications/$(basename "$APP")" 2>/dev/null || true
    info "Installed /Applications/$(basename "$APP")"
    ;;
  *)
    err "unsupported OS: $OS (Windows users: download the .msi from the Releases page)"
    ;;
esac

info "Done. Your reports live in an encrypted vault you create on first launch."
