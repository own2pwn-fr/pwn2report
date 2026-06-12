# pwn2report

> Open-source desktop app for writing security assessment reports — pentest, code audit (SAST), and red team. Local-first, encrypted, beautiful.

`pwn2report` is a [Tauri](https://tauri.app) desktop application (Linux · Windows · macOS) for
writing and exporting professional security reports. Your findings never leave your machine:
everything is stored in a **SQLCipher-encrypted** local database, unlocked by a master
passphrase. Reports are rendered to **PDF** through an embedded [Typst](https://typst.app)
engine — no external binaries, identical output on every OS.

## Design philosophy

A rigid, opinionated core; an open periphery driven by **data, not options**. The finding data
model and the rendering engine are fixed and maintained; all the diversity of what different
testers want lives in **templates and content you own** — not in a thousand config toggles.
If two people want different reports, that's a template, not a setting.

## Status

**Feature-complete against the roadmap (v0–v4).** Three report types, a full finding editor
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

## Future enhancements

- Markdown rich-text inside the PDF (needs a Markdown→Typst conversion).
- Bundling pandoc as a per-OS sidecar (DOCX currently uses pandoc from `PATH`).
- A real-time relay / P2P transport for sync (today: portable encrypted bundle).

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
pnpm tauri dev      # run the app
pnpm tauri build    # produce installers
```

## License

[AGPL-3.0](./LICENSE).
