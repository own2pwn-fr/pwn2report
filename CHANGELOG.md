# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added — v1 backend (multi-format export, templates, vault management)
- Two new report-type Typst themes: `code_audit` (source/file-line + vulnerable-code +
  suggested-patch emphasis) and `red_team` (attack-narrative: scenario → numbered
  exploitation steps → payload). Shared title page / severity table / header-footer factored
  into `lib/common.typ`.
- Editable templates: custom per-report-type Typst templates live at
  `<app_config_dir>/templates/<report_type>.typ`; bundled themes remain the defaults. New
  commands `list_templates`, `get_template`, `save_template`, `reset_template`. PDF export
  prefers the custom template when present.
- Multi-format export: `export_markdown` (GitHub-flavored Markdown), `export_html`
  (self-contained, inline-CSS, own2pwn dark theme), `export_docx` (Markdown piped through
  `pandoc`, resolved from `PATH` or `PWN2REPORT_PANDOC`, styled via a bundled reference doc).
  All consume the same `ReportDocument` IR.
- Vault management: `change_passphrase` (re-verifies the old passphrase, then SQLCipher
  `PRAGMA rekey` on the live connection) and `backup_vault` (WAL checkpoint + file copy of the
  already-encrypted vault).
- New `AppError` variants `Pandoc` and `Io` (serialized as `{kind, message}`).

### Added — v1 frontend (export menu, CVSS calculator, full editor, settings)
- Export menu offering PDF / DOCX / Markdown / HTML, each rendered by the backend then saved
  via the dialog/fs plugins and opened in the OS viewer.
- Interactive CVSS calculator (3.1 + 4.0, via `@pandatix/js-cvss`): live base score, severity
  and vector, wired into the finding form.
- Full finding editor covering the entire model (classification, CVSS, description facets,
  evidence, PoC, remediation, refs/tags, triage) with add/remove rows for list fields.
- `/settings` route: change master passphrase, back up the vault, and edit/reset the per-type
  Typst templates in an in-app editor.

### Deferred to a later iteration
- Markdown rich-text in the PDF (needs a Markdown→Typst conversion; Markdown/HTML exports are
  already Markdown-native). Pandoc is resolved from `PATH` for now; bundling it as a per-OS
  sidecar is a packaging-time concern.

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
