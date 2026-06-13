# Contributing to pwn2report

Thanks for your interest! pwn2report is a Tauri v2 desktop app (Rust backend + React/TS
frontend) for writing security reports. It is licensed **AGPL-3.0** — by contributing you agree
your contribution is licensed under the same terms.

## Dev setup

Requirements: Node ≥ 20 + pnpm, Rust via **rustup** (the toolchain is pinned in
`src-tauri/rust-toolchain.toml` — do not use a distro's system rust), and on Linux the WebKitGTK
dev packages (`webkit2gtk-4.1`, `javascriptcoregtk-4.1`). DOCX export needs `pandoc`.

```bash
pnpm install
bash scripts/fetch-pandoc.sh   # pandoc sidecar for your OS (gitignored)
pnpm tauri dev
```

## Before you open a PR

- **Backend**: `cd src-tauri && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
- **Frontend**: `pnpm exec tsc --noEmit && pnpm test && pnpm exec vite build`
- Keep `en.json` / `fr.json` at exact key parity; route all user-facing strings through i18n.
- Add tests for fixes/features; if you fix a bug, add a test that would have caught it.
- Update `CHANGELOG.md` (and `README.md` / doc comments) when relevant. Don't add standalone
  `.md` docs beyond README/CHANGELOG/CONTRIBUTING/SECURITY — prefer doc comments.

CI runs fmt/clippy/test on Linux, macOS and Windows plus the frontend checks; PRs must be green.

## Project shape (where things live)

- `src-tauri/src/` — Rust: `vault/` (SQLCipher + migrations), `db/`, `models/`, `sync/`,
  `import/`, `ai/`, `render/` (the `ReportDocument` IR feeds Typst/MD/HTML/DOCX/CSV/SARIF),
  `commands/` (the Tauri IPC surface). `resources/typst/` holds the report themes.
- `src/` — React: `app/routes/`, `components/`, `lib/queries/` (TanStack Query over typed
  `lib/ipc.ts`), `i18n/`.

### Non-obvious build pins (don't "fix" these)

- Rust **1.89** (Typst 0.14 MSRV). `time = "=0.3.47"` (0.3.48 breaks `tauri-utils`).
  `rusqlite 0.37` (0.40 needs unstable `cfg_select` on 1.89). The vault stays in
  rollback-journal mode (WAL breaks SQLCipher rekey).

## Adding things

- A **schema migration**: bump `SCHEMA_VERSION` and append an idempotent step (see
  `src-tauri/src/vault/schema.rs`). New columns/tables must also be wired into `sync/`.
- An **importer**: implement the `Importer` trait and register it (`src-tauri/src/import/`).
- A **report template**: themes live in `src-tauri/resources/typst/`; they receive the
  `ReportDocument` IR via `#import sys: inputs` (see `render/content_model.rs` + `lib/common.typ`).

No merge requests to upstream forks please — open a PR against `main`.
