# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Scanner-import robustness & data exports
- **Importer trait + registry**: scanner formats register through an `Importer` trait + a small registry, so
  adding a format is one entry. `import::parse` now returns an `ImportOutcome { findings, warnings }`.
- **Per-record fault tolerance**: a single malformed record (bad JSONL line, missing title, …) is now SKIPPED
  with a warning instead of aborting the whole file. The `import_findings` command returns
  `{ imported, skipped, deduped, warnings }`.
- **Import dedup**: a stable content fingerprint (`title|cwe|cve|primary-evidence-file|severity`) drops exact
  duplicates both within a file and against findings already in the target report.
- **New `Dast` finding kind**: zap/burp/nuclei/nessus now map to `dast`; sarif → `sast`; secai as-provided;
  generic CSV → `manual` (or a `kind` column).
- **Capture all locations**: SARIF multi-location results, ZAP instance URLs, and Burp/Nessus hosts are
  collected (primary in evidence, the rest appended) so dozens of affected URLs/hosts aren't reduced to one.
- **SARIF**: reads `properties.security-severity` (0–10) for severity, resolves rules via `ruleIndex` (CodeQL)
  when `ruleId` is absent, and reads CWE from `result.taxa`/`properties` too.
- **Burp**: extracts CWE from `<vulnerabilityClassifications>` and maps `confidence`
  (Certain/Firm/Tentative → High/Medium/Low).
- **Generic CSV importer** (`format="csv"`): header-driven, case-insensitive column mapping (title/name,
  severity, description, cwe, cve, cvss, host/url, remediation/solution, kind); unknown columns ignored,
  row errors → warnings.
- **Offline CWE name table** (`resources/cwe/cwe-names.json`, ~135 ids): imported findings are annotated with
  the weakness name (e.g. "CWE-89: SQL Injection").
- **New data exports**: `export_csv` (one row per finding) and `export_sarif` (minimal valid SARIF 2.1.0),
  pure functions over the render IR alongside the existing PDF/MD/HTML/DOCX exporters.

### Retest workflow, cloning, custom fields & compliance mappings
- **Retest workflow**: per-finding `retest_status`
  (not_retested/fixed/partially_fixed/not_fixed/risk_accepted) + `retest_date`, shown as a localized badge
  in PDF/HTML/Markdown exports.
- **Compliance mappings**: per-finding framework references (`{framework, id, name?}`, e.g. OWASP/PCI/MITRE),
  rendered as a "References to frameworks" list.
- **Custom fields**: free-form key/value fields on both reports and findings, rendered as a two-column
  Field/Value table.
- **Cloning**: `clone_report` deep-copies a report and all children (scope, assets, findings, evidence image
  bytes, finding↔asset links remapped to the cloned assets, logo) with fresh ids — retest disposition reset.
  `clone_finding` duplicates a finding within its report (with evidence + asset links, retest reset).
- Schema migration to **v7** (idempotent ADD COLUMN). All new columns ride existing reports/findings through
  encrypted sync (LWW); no bundle version bump needed. New localized labels (EN/FR).

### Report depth: assets, scope, engagement metadata, branding
- **Affected-assets model**: a per-report asset inventory (host/ip/url/domain/credential/other) with a
  finding↔asset link, surfaced as an "Affected assets" list per finding and managed in the report.
- **Structured scope**: in-scope / out-of-scope items (replacing the free-text-only scope) rendered as a
  scope table in exports.
- **Engagement metadata**: authors, reviewer, engagement period (dates), reference, and a confidentiality
  banner on the report cover.
- **Per-report branding**: upload a logo (metadata-stripped) shown on the exported cover.
- Schema migration to **v6**; all new tables/columns participate in encrypted sync (LWW + tombstones;
  finding↔asset links union-merge, logos are monotonic — documented). New localized labels (EN/FR).

### Rendering quality
- **HTML exports render Markdown prose** (via pulldown-cmark, raw-HTML stripped) instead of showing
  literal `**bold**`/lists; added a `@media print` light stylesheet.
- **PDF: Table of Contents + real numbered headings** (findings are now proper `heading(level:2)` with
  a severity-badge prefix, so they appear in the outline), a **findings summary table**, and a
  **severity distribution bar** in the overview.
- **CVSS decoded**: a v3.1/v4.0 vector parser renders a localized labelled metric grid (+ severity-colored
  score) instead of the raw vector string.
- **Code blocks** are breakable and wrap long lines; **images** are height-constrained with numbered
  figure captions.
- **MD→Typst converter** gained tables, blockquotes and nested lists, and stops over-escaping ordinary
  text (`-`/`'`/`/` no longer backslashed mid-word).
- **DOCX `reference.docx` rebranded**: violet accent (#7c5cff), Inter headings/body, JetBrains Mono code —
  so Word output matches the PDF/HTML instead of stock pandoc styling.

### Security hardening
- **Content-Security-Policy** set (was `null`): locks script/connect/img/style sources so a DOM-injection
  bug in the webview can't pivot to the unlocked-vault IPC surface.
- **Destructive redaction**: the annotator now deletes the original after saving the redacted image, and
  deletes wipe the image BLOB (`data = X''`, with `secure_delete=ON`) so the un-redacted original is truly
  destroyed and never travels in exports or sync bundles.
- **EXIF/metadata stripped from imported images** (canvas re-encode) so screenshots' GPS/device data don't
  leak into the vault/exports.
- **AI SSRF guard**: the provider `base_url` is validated (http/https only; cloud providers require https
  unless loopback). **Prompt-injection mitigation**: untrusted (possibly imported) field text is fenced and
  the model is told to treat it as data, never instructions. AI assist now previews (accept/reject) instead
  of overwriting the field.
- **Vault passphrases zeroized** (`Zeroizing`) in the PRAGMA key/rekey buffers; unused `argon2` dep removed.
- **DOCX export** uses a private (0700) auto-removed temp dir (`tempfile`) instead of world-readable `/tmp`,
  fixing decrypted-evidence leakage and cleanup-on-crash.
- **Import size cap** (64 MB) to bound memory/CPU on malformed/huge scanner files.
- Styled `AlertDialog` confirmations replace all native `window.confirm` (with Undo on report/finding delete).

### Data-integrity fixes (storage + sync)
- **Real migration framework**: the schema is now applied through an ordered, idempotent
  migration ladder keyed off `PRAGMA user_version` (previously stamped but never read). Fresh
  installs run v1..v5; older vaults run only their missing steps. `SCHEMA_VERSION` bumped to **5**.
- **Forward-compat guard**: opening a vault whose on-disk schema is newer than the running build
  is refused with a new `IncompatibleVault` error instead of silently downgrading.
- **Connection hardening pragmas** on every create/open: `busy_timeout=5000`, `secure_delete=ON`,
  `foreign_keys=ON` (deliberately staying in rollback-journal mode — WAL breaks SQLCipher rekey).
- **Atomic multi-field updates**: report/finding/KB `update` now issue a single parameterized
  `UPDATE` built from the present patch fields (preserving the `Some(None)`=clear semantics),
  fixing torn per-field writes that could leave a stale `updated_at` and let a concurrent sync
  silently revert an edit.
- **Soft-delete + tombstones (sync deletes propagate)**: deletes set a `deleted_at` tombstone
  (added to every syncable table) and bump `updated_at`; live queries filter `deleted_at IS NULL`.
  Tombstones travel in the sync bundle and win LWW, so a delete on one device removes the row on
  peers and a stale bundle can no longer resurrect it. `SyncSummary` gains a `deleted` counter.

### Localized exports (EN/FR)
- **Per-report export language**: a `language` column (`reports`, `SCHEMA_VERSION` bumped to **5**,
  idempotent `ADD COLUMN … DEFAULT 'en'`) drives all export labels. `Report`/`NewReport`/`ReportPatch`
  gain a `language` field (serde `language`, default `"en"`) so the UI can set it per report.
- **Label dictionary** (`render/labels.rs`): every section title, severity name, and per-finding
  label (Summary/Root cause/Attack vector/…/Remediation/PoC/References/Evidence/Screenshots/CVSS,
  report-type names, "no findings" fallback) has full English + French tables; unknown codes fall
  back to English. The labels + language flow through the `ReportDocument` IR into every renderer.
- **Renderers read labels, not literals**: Markdown/HTML/DOCX and the three Typst themes emit the
  localized strings; HTML sets `<html lang="…">` and the themes `#set text(lang: doc.lang)` so
  hyphenation/typography follow the report language. (Dates stay ISO `YYYY-MM-DD`.)

### Editor robustness (data-loss guards)
- **Finding editor**: dirty-state tracking with a discard-confirm dialog and a localStorage draft
  (restored on reopen, cleared on save) so an accidental close/crash no longer loses the in-progress
  finding; inline validation (CWE/CVE format, evidence line ranges); stable list-row keys.
- **Autosave feedback**: the debounced report-prose autosave now flushes on unmount (no lost last
  keystrokes) and shows a "Saving…/Saved" status.

### Hardening, packaging & tooling
- **Markdown rich-text in the PDF**: a compile-safe Markdown→Typst converter renders prose
  (bold/italic/code/lists/links/headings) in PDF exports; Markdown/HTML/DOCX keep raw text.
- **Pandoc bundled as a Tauri sidecar** (`externalBin`) with a `scripts/fetch-pandoc.sh` helper;
  DOCX resolves pandoc from the override env var → the bundled sidecar → `PATH`.
- **End-to-end integration tests** over a real SQLCipher vault (create → render all formats →
  import → sync round-trip between two vaults → rekey → backup).
- **Frontend unit tests** (Vitest) for image/format/IPC helpers and the CVSS calculator; JS
  bundle split into vendor chunks (no more >500 kB warning).
- **CI** (GitHub Actions): `cargo fmt`/`clippy -D warnings`/`test` on Linux/macOS/Windows,
  frontend typecheck/test/build; a tag-triggered **release** workflow (`tauri-action`) with
  code-signing slots documented.
- **own2pwn app icon**; explicit privacy warning when a cloud AI provider is selected.
- Backend is `clippy -D warnings` clean and `rustfmt`-formatted.

### Added — v4 (end-to-end encrypted sync, local-first)
- Portable **sync bundle** (`.p2r`): an `age` passphrase-encrypted snapshot of the whole vault
  (reports, findings, KB, evidence images). Move it between devices by any means (USB,
  Syncthing, Nextcloud, …) — no server, local-first preserved.
- Conflict-free **LWW merge** keyed by UUID + `updated_at` (a CRDT strategy): reports →
  findings → KB → images, in one transaction; newer rows win, images are insert-only.
- Commands `export_sync_bundle` / `import_sync_bundle` (returns a merge summary); Sync section
  in Settings. (A real-time relay/P2P transport remains a future enhancement.)

### Added — v3 (pluggable AI, runtime i18n, onboarding)
- Pluggable AI assistance, **opt-in and OFF by default**: Ollama (local) or a cloud API
  (OpenAI-compatible / Anthropic). Config in `<app_config_dir>/ai.json`; the API key lives in
  the OS keychain. Commands `ai_get_config`, `ai_set_config`, `ai_test_connection`,
  `ai_complete`. AI-assist (✨ improve/generate/summarize/translate) on finding description
  facets, remediation, and the exec summary — only shown when enabled.
- Runtime language switching with a complete **French** locale (full `fr.json` parity); choice
  persisted; switcher in Settings.
- First-run onboarding tour + tooltips on key icon actions.

### Added — v2 round 2 (evidence-image pipeline)
- Per-finding evidence images stored in the SQLCipher-encrypted vault
  (`evidence_images` table, bytes as a BLOB → encrypted at rest). Schema migration to v3
  (idempotent, `PRAGMA user_version`).
- New commands: `add_evidence_image`, `list_evidence_images`, `get_evidence_image`,
  `update_evidence_caption`, `delete_evidence_image`, `reorder_evidence_images`.
- Images are embedded in every export format: PDF (Typst `image()` figures via a new
  `finding-images` helper in `lib/common.typ`, used by all three themes), HTML and Markdown
  (inline base64 `data:` URIs, self-contained), and DOCX (images written to a temp dir and
  referenced by relative path so pandoc embeds them via `--resource-path`).

### Added — v2 (knowledge base & scanner importers)
- Vulnerability knowledge base: reusable finding templates stored in the encrypted vault
  (`kb_entries`), a bundled catalog of 13 common web/app vulnerabilities, full CRUD, an
  "import bundled catalog" action, "Add from KB" to pre-fill a report finding, and a `/kb`
  management page (search/filter/edit).
- Scanner importers: SARIF, Nuclei, ZAP, Burp, Nessus and secai/EASM native JSON via
  `import_findings(report_id, format, content)`; an in-report import dialog reads the file and
  bulk-adds findings. Defensive per-tool severity mapping; `roxmltree` for the XML formats.
- Schema migration to v2 (idempotent, `PRAGMA user_version`).

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

### Still deferred
- A real-time relay / P2P transport for sync (today: a portable encrypted bundle).

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
