# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — v0 technical skeleton
- Tauri v2 + Vite/React/TypeScript desktop shell (Linux · Windows · macOS).
- SQLCipher-encrypted local vault: create/unlock by master passphrase, optional OS-keychain
  storage, canary-based passphrase validation.
- Finding data model mirroring the secai-core `Finding` shape (severity, CVSS, CWE/CVE,
  description facets, remediation, evidence, PoC), stored with JSON sub-objects.
- Reports + findings CRUD over a typed Tauri IPC surface.
- `web_pentest` report type with a Typst theme; PDF export via an embedded Typst engine
  (`typst-as-lib`), brand-styled with Inter + JetBrains Mono.
- own2pwn-styled UI (dark/light, violet accent) with `motion` micro-interactions, i18n scaffold.

### Build notes
- Rust toolchain pinned to 1.89 (`src-tauri/rust-toolchain.toml`) to match Typst 0.14's MSRV.
- `time` pinned to `=0.3.47`: `time 0.3.48` introduces an impl that trips a coherence check
  (E0119) in `tauri-utils 2.9.2`. 0.3.47 still satisfies the transitive `plist` floor.
- `rusqlite` pinned to 0.37 (libsqlite3-sys 0.35): rusqlite 0.40's libsqlite3-sys 0.38 uses the
  unstable `cfg_select!` macro in its build script, which fails on Rust 1.89.
