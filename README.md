# PSPM — Password Security Posture Management

A local-first, privacy-respecting platform that audits, cleans, and strengthens your Bitwarden (and other password manager) vaults. Runs entirely on your machine — nothing leaves your network unless you explicitly opt in.

## Architecture

```
Vault Export (.json/.csv)
        │
        ▼
   Import Engine
        │
        ▼
Encrypted Local Database (SQLite + SQLCipher)
        │
  ┌─────┼──────────┐
  │     │          │
  ▼     ▼          ▼
Analysis Cleanup  Automation
  │     │          │
  └─────┼──────────┘
        ▼
   AI Assistant
(Metadata-only by default)
        │
        ▼
  Updated Vault Export
        │
        ▼
   Import to Bitwarden
```

## Features

| Module | Description |
|--------|-------------|
| **Import** | Bitwarden JSON/CSV, KeePass, 1Password, Proton Pass, LastPass |
| **Analysis** | Reuse, weakness, age, MFA coverage, duplicates, compromise |
| **Strength** | Entropy, charset, dictionary attacks, keyboard walks, dates |
| **Breach Detection** | HIBP k-Anonymity API (SHA‑1 prefix, never full password) |
| **Duplicate Detection** | Same website, username, password hash, URI, title |
| **AI Assistant** | Metadata‑only by default (Level 0). Suggests folders, tags, cleanup |
| **Live Login Checker** | Playwright automation — user approves each attempt |
| **Password Rotation** | Recipe‑based auto‑rotation with manual fallback |
| **Password Generator** | Random, Diceware, PIN, memorable — site‑specific policies |
| **Security Dashboard** | Overall score, grade distribution, breach stats |
| **Export** | Bitwarden JSON/CSV, KeePass, encrypted backup |

## AI Security Model

| Level | Access | Default |
|-------|--------|---------|
| **Level 0** | Titles, URLs, folder names, tags, metadata | ✅ Default |
| **Level 1** | + password length, entropy, breach status, hashes | ❌ Opt-in |
| **Level 2** | + plaintext password (single op, volatile memory only) | ❌ Explicit approval |

The AI never receives plaintext passwords, TOTP secrets, recovery codes, or private keys unless you explicitly approve a Level 2 operation.

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.80+
- [Node.js](https://nodejs.org/) 20+
- (Optional) [Ollama](https://ollama.ai/) for local AI suggestions

### Setup

```bash
# Clone
git clone https://github.com/naviNBRuas/PSPM.git
cd PSPM

# Build frontend
cd frontend
npm install
npm run build
cd ..

# Build and run backend
cargo run --release
```

### Access

Add to `/etc/hosts`:
```
127.0.0.1 pspm.localhost
```

Open **[http://pspm.localhost:8080](http://pspm.localhost:8080)**

### Development

```bash
# Terminal 1 — Backend (auto-reloads)
cargo watch -x run

# Terminal 2 — Frontend (Vite dev server, proxies /api to Rust)
cd frontend && npm run dev
```

## Privacy & Security

- **All processing is local.** Your vault data never touches an external server.
- **Passwords are hashed on import.** SHA‑1 for HIBP, SHA‑256 for internal dedup.
- **HIBP checks use k-Anonymity.** Only the first 5 hex chars of your SHA‑1 hash are sent.
- **Database is encrypted** with SQLCipher (AES‑256).
- **Plaintext passwords exist only in volatile memory** during import and are discarded immediately after hashing.

## Tech Stack

- **Backend:** Rust + Axum
- **Database:** SQLite + SQLCipher
- **Frontend:** React + TypeScript + Vite + Tailwind CSS
- **Automation:** Playwright (optional, for live login checking)
- **AI:** Ollama (local), optional OpenAI/Anthropic with consent

## License

MIT

---

Built by [Navin B. Ruas](https://nbr.company)
