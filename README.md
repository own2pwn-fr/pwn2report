# pwn2report

> Open-source desktop app for writing security assessment reports — pentest, code audit (SAST), and red team. Local-first, encrypted, beautiful.

[![CI](https://github.com/own2pwn-fr/pwn2report/actions/workflows/ci.yml/badge.svg)](https://github.com/own2pwn-fr/pwn2report/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-7c5cff.svg)](./LICENSE)
![Platforms: Linux · Windows · macOS](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20%C2%B7%20macOS-555)

`pwn2report` is a [Tauri](https://tauri.app) desktop application (Linux · Windows · macOS) for
writing and exporting professional security reports. Your findings never leave your machine:
everything is stored in a **SQLCipher-encrypted** local database, unlocked by a master
passphrase. Reports are rendered to **PDF** through an embedded [Typst](https://typst.app)
engine — for PDF, no external binaries, with identical output on every OS. (DOCX export uses
`pandoc`; see Install.)

## Design philosophy

A rigid, opinionated core; an open periphery driven by **data, not options**. The finding data
model and the rendering engine are fixed and maintained; all the diversity of what different
testers want lives in **templates and content you own** — not in a thousand config toggles.
If two people want different reports, that's a template, not a setting.

## Status

**Feature-complete, hardened, and audited.** Three report types, a full finding editor
with an interactive CVSS 3.1/4.0 calculator, multi-format export (PDF / DOCX / Markdown /
HTML), editable Typst templates, a reusable vulnerability knowledge base, scanner importers,
an evidence pipeline (gallery + annotator/redactor), opt-in pluggable AI assistance, runtime
EN/FR localization, onboarding, and end-to-end encrypted local-first sync.

## Features

- 🔐 **Local-first & encrypted** — SQLCipher database, passphrase unlock, optional OS keychain,
  in-app passphrase change + vault backup.
- 📝 **Full structured findings** — severity, interactive CVSS 3.1/4.0, CWE/CVE, description
  facets, remediation, evidence, PoC, refs/tags, triage.
- 📄 **Multi-format export** — PDF (embedded Typst, brand-styled), DOCX (via pandoc), Markdown,
  self-contained HTML.
- 🧩 **Three report types + editable templates** — web pentest, code audit, red team; edit the
  Typst templates in-app.
- 📚 **Knowledge base** — reusable finding templates (bundled catalog + your own); add to a
  report in one click.
- 📥 **Importers** — SARIF, Nuclei, ZAP, Burp, Nessus and secai/EASM native JSON.
- 🖼️ **Evidence pipeline** — attach screenshots, annotate, and redact (baked-in), embedded in
  every export.
- 🤖 **Opt-in AI assistance** — Ollama (local) or a cloud API; off by default, nothing leaves
  the machine unless you enable it.
- 🌍 **EN / FR** UI with runtime switching · first-run onboarding.
- 🔁 **E2E-encrypted sync** — portable encrypted bundle, conflict-free merge, no server.
- 🎨 **own2pwn look** — dark/light, violet accent, smooth micro-interactions.

Beyond the original roadmap it also has: an affected-assets/scope model, engagement metadata &
per-report branding, report/finding cloning, a retest workflow, custom fields, compliance
mappings, CSV/SARIF export, Azure/Gemini AI providers, and a hardened security & accessibility pass.

## Install

Grab an installer for your OS from the [Releases](https://github.com/own2pwn-fr/pwn2report/releases)
page (`.deb`/`.rpm`/AppImage on Linux, `.msi` on Windows, `.dmg` on macOS).

- **DOCX export** needs [`pandoc`](https://pandoc.org/installing.html) — release builds bundle it;
  if you run from source, install pandoc or set `PWN2REPORT_PANDOC` to its path.
- **Linux** also needs the WebKitGTK runtime (`webkit2gtk-4.1`).

## Usage

There is **no account and no server** — "logging in" means unlocking your local encrypted vault.

1. **First run** → *Create your vault* with a master passphrase (optionally remember it in the OS
   keychain). ⚠️ There is **no passphrase recovery** — if you lose it, the vault is unrecoverable.
2. **New report** (web pentest / code audit / red team) → fill scope, assets, engagement metadata.
3. **Add findings** — manually, **from the knowledge base**, or by **importing** scanner output
   (SARIF / Nuclei / ZAP / Burp / Nessus / CSV / secai). Attach & annotate/redact evidence.
4. **Export** to PDF / DOCX / Markdown / HTML / CSV / SARIF; pick the report's language (EN/FR).
5. **Sync** between machines via Settings → an end-to-end encrypted `.p2r` bundle.

## Future enhancements

- A real-time relay / P2P transport for sync (today: portable encrypted bundle).
- Outbound integrations (push to Jira / DefectDojo / GitLab issues).

## Troubleshooting

- **DOCX export fails** → install `pandoc` (or set `PWN2REPORT_PANDOC`).
- **Forgot the passphrase** → unrecoverable by design; restore from a backup/sync bundle if you have one.
- **Linux: blank window / launch error** → install `webkit2gtk-4.1`.
- **Build from source: cargo errors** → use rustup (the repo pins Rust 1.89); don't use a distro's system rust.

## Tech stack

| Layer | Choice |
|---|---|
| Shell | Tauri v2 |
| Frontend | Vite + React + TypeScript + shadcn/ui + Tailwind, `motion` |
| Storage | SQLite + SQLCipher (rusqlite, bundled), `keyring` for OS keychain |
| PDF | Typst, embedded in-process (`typst-as-lib`) |
| Data model | mirrors the secai-core `Finding` shape |

## Development

Requires Node ≥ 20 + pnpm, and Rust (the toolchain is pinned via
`src-tauri/rust-toolchain.toml` to match Typst's MSRV). On Linux you also need the WebKitGTK
dev packages (`webkit2gtk-4.1`, `javascriptcoregtk-4.1`).

```bash
pnpm install
bash scripts/fetch-pandoc.sh   # fetch the pandoc sidecar for your OS (gitignored)
pnpm tauri dev                 # run the app
pnpm tauri build               # produce installers

# tests
pnpm test                      # frontend (Vitest)
cd src-tauri && cargo test     # backend (incl. end-to-end integration tests)
```

DOCX export needs `pandoc`: it is bundled as a sidecar for release builds (`scripts/fetch-pandoc.sh`),
and otherwise resolved from `PATH` (or the `PWN2REPORT_PANDOC` env var). CI builds/tests on
Linux, macOS and Windows; tagging `v*` builds signed installers via the release workflow.

## Contributing & security

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup and the PR checklist, and
[SECURITY.md](./SECURITY.md) for the threat model and how to report a vulnerability privately.

## License

[AGPL-3.0](./LICENSE). Note the AGPL §13 network clause: if you offer a modified version to users
over a network, you must make your modified source available to them.
