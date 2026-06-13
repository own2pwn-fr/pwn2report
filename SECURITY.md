# Security Policy

pwn2report stores highly sensitive data (vulnerabilities, credentials, client material under
NDA). We take its security seriously.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Use GitHub's **[Report a vulnerability](https://github.com/own2pwn-fr/pwn2report/security/advisories/new)**
  (Security → Advisories), or
- email **contact@own2pwn.fr** with the details and, if possible, a proof of concept.

We aim to acknowledge within a few days and to ship a fix promptly for confirmed issues. Please
give us a reasonable window to remediate before any public disclosure.

## Scope

In scope: the desktop application and its data handling — vault encryption, the sync bundle,
the AI integration, importers (which parse untrusted scanner output), and report rendering.

## Threat model & guarantees

**What is protected**

- **Data at rest** is in a SQLCipher-encrypted SQLite vault, unlocked by a master passphrase
  (the passphrase derives the key; it is not stored, only optionally cached in the OS keychain).
  Evidence image bytes live in the encrypted DB. `secure_delete` is on.
- **Local-first**: nothing leaves the machine unless you explicitly enable it. The optional AI
  assistant is **off by default**; a cloud provider only receives report text when you turn it on.
- **Sync bundles** (`.p2r`) are end-to-end encrypted with `age` under a passphrase you choose;
  the plaintext snapshot never touches disk on export.
- **Redaction** in the evidence annotator is destructive: the redacted pixels are baked in and
  the un-redacted original is deleted (its bytes wiped) — it does not travel in exports/sync.
- Imported images are re-encoded to strip EXIF/GPS metadata. XML imports are XXE-safe.
- A Content-Security-Policy constrains the webview.

**What is NOT protected / your responsibility**

- **There is no passphrase recovery.** If you lose the master passphrase, the vault is
  unrecoverable by design.
- An attacker with code execution on your unlocked machine, or who reads process memory while
  the vault is unlocked, can access the data. Lock the vault (or use the idle auto-lock) when away.
- The sync bundle's trust is symmetric: anyone with the bundle passphrase can read or forge one.
- Enabling a **cloud** AI provider sends report content to that third party — use the local
  (Ollama) provider when confidentiality requires it.

## Supported versions

Until a 1.0 release, only the latest `main`/release is supported with security fixes.
