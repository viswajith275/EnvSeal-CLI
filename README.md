```text
 /$$$$$$$$                       /$$$$$$                      /$$
| $$_____/                      /$$__  $$                    | $$
| $$       /$$$$$$$  /$$    /$$| $$  \__/  /$$$$$$   /$$$$$$ | $$
| $$$$$   | $$__  $$|  $$  /$$/|  $$$$$$  /$$__  $$ |____  $$| $$
| $$__/   | $$  \ $$ \  $$/$$/  \____  $$| $$$$$$$$  /$$$$$$$| $$
| $$      | $$  | $$  \  $$$/   /$$  \ $$| $$_____/ /$$__  $$| $$
| $$$$$$$$| $$  | $$   \  $/   |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$
|________/|__/  |__/    \_/     \______/  \_______/ \_______/|__/

```

**An encrypted vault for your API keys and secrets, because `.env` files have never once kept a secret.**

EnvSeal is a zero-trust secrets engine for local development, team collaboration, and production CI/CD. Secrets stay encrypted at rest, get injected only into the process that needs them, and never linger in your shell history or environment. Protected tags, scoped bearer tokens, and DEK rotation give you least-privilege access and a clean way to revoke things when something inevitably leaks.

[Install](#installation) · [Why EnvSeal](#why-this-exists) · [Quick Start](#quick-start) · [Commands](#commands) · [Security Model](#cryptographic-hierarchy) · [Troubleshooting](#troubleshooting)

---

## Installation

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

The installer detects your platform, places the binary in `~/.local/bin`, updates your `PATH`, and adds a small shell helper so `envseal load` works without a manual `eval`. Bash, zsh, and fish are all supported.

Prefer to inspect a script before piping it into `bash`? Download it first:

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh -o install.sh
less install.sh   # review it
bash install.sh
```

Other install methods (pinned version, local binary, from source) are listed under [Other Installation Options](#other-installation-options).

---

## Upcoming

**Local proxy** : Securely handling secrets by injecting real credentials into network traffic via a local proxy, keeping them out of process memory and environment variables. This prevents sensitive credentials from being exposed in memory or environment variables, mitigating risks from memory dumps, malicious dependencies, or insecure configuration practices. (Normal variables will be injected as usual specially configured ones will be injected by the proxy)

## Why This Exists

Plaintext secrets get copied into `~/Downloads`, scattered across scripts, and occasionally pushed straight to GitHub. Scraper bots pick up newly committed keys within minutes. One misdirected key and a local script writes to production or emails real customers. Sourcing a `.env` file pollutes every process in your shell session. Sharing production credentials with a team usually means pasting them into Slack or committing a file helpfully named `prod.env.final`.

EnvSeal encrypts everything at rest, scopes access tightly by tag and token, and injects secrets only for the lifetime of a single child process — never into your interactive shell unless you explicitly ask for that with `load`.



| Feature                      | `.env`           | dotenvx          | SOPS                   | EnvSeal               | Doppler                  |
| ---------------------------- | ---------------- | ---------------- | ---------------------- | --------------------- | ------------------------ |
| Encrypted secrets            | No               | Yes              | Yes                    | Yes                   | Yes                      |
| Works offline                | Yes              | Yes              | Yes                    | Yes                   | No                       |
| Run a command with secrets   | Yes*             | Yes              | Limited                | Yes                   | Yes                      |
| No cloud account needed      | Yes              | Yes              | Yes                    | Yes                   | No                       |
| CI/CD support                | Limited          | Yes              | Yes                    | Yes                   | Yes                      |
| Secret scopes / environments | No               | Limited          | No                     | Yes                   | Yes                      |
| Built-in secret rotation     | No               | Limited          | No                     | Yes                   | Yes                      |
| Local-first                  | Yes              | Yes              | Yes                    | **Yes**               | No                       |
| Simple setup                 | **Very simple**  | Simple           | Moderate               | **Simple**            | Simple                   |
| Main idea                    | Plaintext config | Encrypted `.env` | Encrypted config files | Encrypted env secrets | Hosted secret management |


* `.env` can provide variables to a process, but the secrets remain stored as plaintext.


* **EnvSeal keeps the simplicity of `.env` while encrypting secrets on disk and injecting them only when your application runs.**

* No server. No account. No complicated setup.

* That is the main difference from larger secret-management platforms: **EnvSeal is designed to stay small, local, and easy to use.**


---

## Real-World Wins Over `.env`

**Solo developer**

Store personal keys in the global vault, link a project once, and run:

```bash
envseal run ./deploy.sh
```

No more hunting for the right file or accidentally committing one. If your laptop is stolen, the attacker gets ciphertext, not credentials.

**Small team**

Commit a local `.envseal` file to the repo. Everyone unlocks development secrets with a shared master password. Production Stripe and database credentials live under a protected tag that requires a second, separate password known only to whoever deploys. Junior developers get a fully working repo without ever touching production keys.

**CI/CD without sharing the master password**

Mint a short-lived, least-privilege token:

```bash
envseal token -t prod -o ./.token --exp 3600
```

Mount the token file (or inject it via `ENVSEAL_TOKEN` / `ENVSEAL_TOKEN_FILE`) into the runner. The pipeline can decrypt only what the token scopes it to. The master password never leaves the developer's machine.

**Leaked token?**

```bash
envseal rotate --tag prod
```

Every token issued against that scope stops working immediately. Then rotate the underlying credentials the token could reach — database passwords, API keys, and so on. Expiration is a convenience, not a revocation mechanism, so don't wait for a token to time out on its own.

**"Which `.env` is even loaded right now?"**

Stop guessing and switch deliberately:

```bash
envseal -e staging run npm start
envseal -e prod run npm start
```

Or use tags inside a single profile when only a handful of values differ between environments.

---

## What You Get

**Local & Global Vaults**

Project-scoped `.envseal` files that are safe to commit, or a system-wide vault for personal scripts and one-off tooling.

**Protected Tags**

Share one vault for everyday development keys while locking high-stakes variables behind a completely separate secondary password.

**Zero-Trust Bearer Tokens**

Mint least-privilege tokens scoped to an entire tag or to specific keys. Tokens never embed the master password, the KEK, or the signing key. They're compressed with zstd, carry `iat`/`exp` claims, and are only ever ingested via file, environment variable, or stdin — never as a CLI flag, so they don't leak into `ps` output or shell history.

**DEK Rotation**

`envseal rotate` generates a fresh Data Encryption Key for a scope, re-encrypts everything under it, and immediately invalidates every existing token for that scope.

**Cryptographic Hierarchy**

Master password → Argon2id → KEK → Master DEK → HKDF-derived Scope DEKs → per-variable Entry Keys. Secrets are never encrypted directly under the password itself. Every vault mutation is signed with an Ed25519 key derived alongside the KEK, and unlocking the vault verifies that signature against the embedded public key.

**Session Caching**

Derived cryptographic material — never the raw password — is cached in the OS keyring for about 10 minutes, dropping subsequent command latency from hundreds of milliseconds to single digits.

**Storage & Integrity**

MessagePack encoding with deterministic ordering, raw binary payloads, and atomic filesystem writes. All sensitive in-memory buffers implement `Zeroize` / `ZeroizeOnDrop` so key material doesn't linger after use.

**Cross-Platform**

Linux, macOS (Apple Silicon), and Windows.

---

## Quick Start

### Local Project (Teams)

```bash
# 1. Create a local vault
envseal init --local

# 2. Store development secrets
envseal set DATABASE_URL
envseal set API_KEY

# 3. Protect production behind a secondary password
envseal protag prod
envseal set --tag prod STRIPE_SECRET

# 4. Run with secrets injected only into the child process
envseal run npm start
envseal run --tag prod npm start

# 5. Clear the session when you step away
envseal clear
```

### Global Vault (Personal Scripts)

```bash
envseal --global init
envseal --global link myapp
envseal --global set AWS_ACCESS_KEY
envseal --global run ./deploy.sh
```

### Multi-Profile Files

```bash
envseal -e staging init --local
envseal -e staging set API_URL
envseal -e staging run npm start
```

### CI/CD with a Token

```bash
# On a developer machine (once)
envseal token -t prod -o ./.token --exp 7200 -n "ci-prod" -d "GitHub Actions deploy"

# In the pipeline
export ENVSEAL_TOKEN_FILE=./.token
envseal run --tag prod --token-file ./.token npm run migrate
```

Or pipe it in directly:

```bash
cat .token | envseal run --tag prod npm start
```

---

## Commands

| Command | Description |
|---|---|
| `envseal init [--local]` | Create a new encrypted vault. |
| `envseal set [-g GROUP] [-t TAG] KEY` | Store or update a secret. |
| `envseal get [-g GROUP] [-t TAG] [--token-file PATH] KEY` | Print a single decrypted value. |
| `envseal protag [-g GROUP] TAG` | Create a protected tag (secondary password). |
| `envseal import [-g GROUP] [-t TAG] PATH` | Import a plaintext `.env` file. |
| `envseal export [-g GROUP] [-t TAG] [--token-file PATH] [-o PATH] [KEYS...]` | Write secrets to a `.env` file. |
| `envseal run [-g GROUP] [-t TAG] [--token-file PATH] -- CMD` | Run a command with secrets injected into that process only. |
| `envseal load [-g GROUP] [-t TAG] [--token-file PATH] [KEYS...]` | Output shell export statements (prefer `run`). |
| `envseal list [-g GROUP] [-t TAG]` | List key names (never values). |
| `envseal remove [-g GROUP] [-t TAG] [KEY]` | Delete a key, tag, or group. |
| `envseal link GROUP` | Bind a global group to the current directory. |
| `envseal clear` | Flush cached cryptographic material from the OS keyring. |
| `envseal token [-g GROUP] [-t TAG] [-n NAME] [-d DESC] [-o PATH] [--exp SECS] [KEYS...]` | Mint a zero-trust bearer token. |
| `envseal rotate [-g GROUP] [-t TAG]` | Rotate the DEK for a scope and invalidate existing tokens. |

**Global flags**

| Flag | Description |
|---|---|
| `-e, --env <NAME>` | Target a profile (e.g. `-e prod` reads/writes `.prod.envseal`). |
| `-G, --global` | Force the global system vault instead of a local one. |

---

## Token Ingestion

Tokens never appear as command-line arguments. Use one of the following instead:

| Method | How | Best for |
|---|---|---|
| Token file | `--token-file /path/to/.token` | Kubernetes secrets, Docker volumes |
| Environment | `ENVSEAL_TOKEN` or `ENVSEAL_TOKEN_FILE` | GitHub Actions, GitLab CI, and similar |
| Stdin | `cat token.file \| envseal run ...` | Ad hoc scripts (uses `IsTerminal` checks so child processes still get their own stdin) |

Token files created with `-o` receive `0600` permissions automatically.

**Warning:** Treat token expiration (`--exp`) as a convenience, not a hard security boundary. Clocks drift, tokens get copied, and "it expires in an hour" is not a revocation strategy. If a token is compromised — or even just suspected of being compromised — always:

1. Rotate the DEK for the affected scope: `envseal rotate ...`
2. Rotate the actual credentials the token could reach (database passwords, API keys, and so on).

---

## Best Practices

- Prefer `envseal run` over `envseal load`. `load` leaves secrets sitting in your live shell; `run` scopes them to a single child process and nothing else.
- Never put the master password in CI. Mint short-lived, least-privilege tokens instead.
- Don't rely on token expiration alone. On any compromise, or even suspicion of one, rotate the DEK **and** the underlying credentials.
- Keep production behind protected tags or separate profiles, and share those secondary passwords narrowly.
- Run `envseal clear` when you step away from a shared or unattended machine.
- Back up vault files — they're already encrypted, so a backup is not a new exposure.

---

## Troubleshooting

**"Seal already exists"**
You're trying to `init` where a vault is already present. Use the existing vault, or remove it first if you're sure you want to start over.

**"No group linked to current directory"**
Run `envseal --global link <groupname>` first.

**Signature / integrity verification failed**
The vault file was modified or corrupted outside of EnvSeal. Restore it from a backup or re-import your secrets.

**Token decryption fails after a rotate**
Expected — the old DEK is gone. Mint a new token against the updated vault, and make sure the underlying credentials have been rotated too if the old token was ever compromised.

**Repeated password prompts**
Confirm the OS keyring service is running. If it is and prompts still repeat, run `envseal clear` and try again.

---

## Other Installation Options

**Specific version**

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash -s -- --version v5.0.0
```

**From a locally built binary**

```bash
./scripts/install.sh --file ./target/release/envseal
```

**From source**

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build --release
./scripts/install.sh --file ./target/release/envseal
```

Pre-built binaries for Linux (x86_64/ARM64), macOS (Apple Silicon), and Windows are available on the [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) page.

---

## Contributing

Fork, branch, fix, open a PR. Bug reports, platform testing (especially Windows), and security reviews are all welcome.

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build
cargo test
cargo fmt
cargo clippy
```

---

## License

MIT. Use it, fork it, ship it — just keep the license notice, and never put your master password (or a long-lived token) in a pull request.
