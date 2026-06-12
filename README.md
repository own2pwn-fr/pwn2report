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

**v0 — technical skeleton.** The end-to-end stack is wired and de-risked: encrypted vault
create/unlock (+ optional OS-keychain), a `web_pentest` report type, findings CRUD, and
Typst → PDF export. See the roadmap for what comes next.

## Features (v0)

- 🔐 **Local-first & encrypted** — SQLCipher database, passphrase unlock, optional OS keychain.
- 📝 **Structured findings** — severity, CVSS, CWE/CVE, description facets, remediation, evidence.
- 📄 **PDF export** — embedded Typst engine, brand-styled (Inter + JetBrains Mono).
- 🎨 **own2pwn look** — dark/light, violet accent, smooth micro-interactions.

## Roadmap

- **v1** — 3 report types · interactive CVSS 3.1/4.0 calculator · Markdown + HTML export ·
  DOCX via Pandoc · editable templates · passphrase rekey.
- **v2** — reusable vulnerability knowledge base · evidence with annotation/redaction/gallery ·
  importers (Nessus/Burp/ZAP/Nuclei/SARIF).
- **v3** — pluggable AI assistance (local Ollama or cloud, opt-in, off by default) · runtime i18n · onboarding.
- **v4** — end-to-end encrypted sync (CRDT), local-first preserved.

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
