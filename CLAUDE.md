# pwn2report — notes for AI agents / contributors

Open-source Tauri v2 desktop app for writing security reports (pentest / code audit / red team).
Local-first, SQLCipher-encrypted, Typst-rendered PDFs. AGPL-3.0.

## Architecture (keystone first)

- **`src-tauri/src/render/content_model.rs`** defines `ReportDocument`, the rendering IR.
  EVERY renderer (PDF now; Markdown/HTML/DOCX later) consumes this IR — never DB rows directly.
  This is the seam that keeps "content model = single source, renderers consume" honest.
- **Data model** (`src-tauri/src/models/`) mirrors the secai-core `Finding` shape. The TS twin
  lives in `src/lib/types.ts`. Keep the two in sync; field names match for future import/export.
- **Storage**: `src-tauri/src/vault/` owns the encrypted SQLite connection (rusqlite +
  bundled-sqlcipher). `PRAGMA key` MUST be the first statement on a connection. Passphrase is
  validated via a `canary` row in `meta`. Keychain ops (`keyring`) degrade gracefully — never
  block unlock on keychain availability.
- **IPC**: synchronous `#[tauri::command]` fns (not async — avoids holding the std Mutex guard
  across an await with the non-Sync rusqlite Connection). Errors serialize as `{kind, message}`.
  JS invoke args are camelCase; Rust params snake_case (Tauri auto-maps).
- **Frontend** (`src/`): Vite + React + shadcn/ui + Tailwind, TanStack Query over IPC, `motion`
  for animation, react-i18next (all strings via i18n keys). Design tokens ported from the EASM
  web app (dark default, violet accent, Inter + JetBrains Mono).

## Build gotchas (non-obvious — read before "fixing" deps)

- **Rust toolchain is pinned to 1.89** (`src-tauri/rust-toolchain.toml`) = Typst 0.14's MSRV.
  Build via rustup, not Fedora's system rust.
- **`time` is pinned to `=0.3.47`** in `src-tauri/Cargo.toml`. `time 0.3.48` adds an impl that
  trips an E0119 coherence error inside `tauri-utils 2.9.2`. 0.3.47 still satisfies the
  transitive `plist` floor. Do NOT `cargo update -p time` past 0.3.47 until tauri-utils fixes it.
- **`rusqlite` is pinned to 0.37** (libsqlite3-sys 0.35). rusqlite 0.40 pulls libsqlite3-sys
  0.38, whose build script uses the unstable `cfg_select!` macro → fails on Rust 1.89. 0.37 keeps
  the MSRV at Typst's 1.89. Don't bump rusqlite past 0.37 without also raising the toolchain.
- **Typst versions are coupled**: `typst`, `typst-pdf` (0.14) and `typst-as-lib` (0.15.5) must
  move together. Fonts are embedded via `include_bytes!` from `src-tauri/resources/fonts/`.
- First `cargo build` is slow (SQLCipher C compile + the whole Typst tree). Verify once at the
  top level — don't run `cargo build` inside throwaway sub-steps.

## Conventions

- New work → feature branch, run tests/linters before pushing, commit with a clear message,
  merge directly (no MR). Update README/CHANGELOG/this file when relevant.
- No standalone `.md` docs beyond README/CHANGELOG/CLAUDE.md — document in code (doc comments).
- Templating diversity belongs in `.typ` templates/content, not in new config options.
