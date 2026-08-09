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

An encrypted vault for your API keys and secrets, because `.env` files have never once kept a secret.

EnvSeal keeps your credentials organized, scoped, and locked down with AES-256-GCM encryption. It runs on a hybrid model: maintain a global vault for personal tools, or generate project-specific, git-committable `.envseal` files for team collaboration. Isolated environment profiles, session caching, and protected tags mean no more plaintext `.env` files sitting around waiting for a stray `git add .` to ruin your week.

## The Problem (Yes, You've Done This)

- Plaintext secrets everywhere. `.env` files get copied into `~/Downloads`, scattered across projects, and inevitably pushed to GitHub. Bots scrape new public commits for exposed keys within minutes. Suddenly you're rotating credentials at 2 a.m.
- Environment mix-ups. One misplaced key and your local script is mutating the production database or emailing real customers.
- Global shell pollution. Source a `.env` and every background process, cron job, and nosy subshell can read your Stripe key.
- Collaboration risks. Sharing secrets across a team usually ends with someone pasting production credentials into Slack.

## The Solution

EnvSeal encrypts everything at rest and injects secrets strictly into the target process via `envseal run`. Your parent shell stays clean. It acts as a zero-trust bouncer for your environment variables: checks ID, lets the right process in, and remembers nothing afterward.

## Real-World Use Cases

**The solo developer**  
Keep personal keys (OpenAI, AWS, Stripe test mode) in the global vault. Link a project once, then:

```bash
envseal run ./deploy.sh
```

No more hunting for the right `.env` or accidentally committing one. If the laptop walks away, the vault is just ciphertext without the master password.

**The small team that doesn't want juniors seeing production Stripe keys**
 
Initialize a local `.envseal`, commit it, and share the master password for development secrets. Put production credentials under a protected tag that requires a second password known only to the people who actually deploy. Everyone can `git pull` and start working; production stays cryptographically locked.

**CI/CD that doesn't leave secrets lying around**  
Set `ENVSEAL_PASSWORD` (and `ENVSEAL_TAG_PASSWORD_PROD` if needed) in your pipeline secrets. The job stays fully non-interactive:

```bash
envseal run --tag prod npm run migrate
envseal run --tag prod npm start
```

Secrets exist only for the lifetime of those processes. When the job ends, they're gone.

**The classic "which `.env` is loaded right now?" disaster**  
Instead of juggling `.env`, `.env.staging`, `.env.production` and the inevitable mix-up, switch deliberately:

```bash
envseal -e staging run npm start
envseal -e prod run npm start
```

Or use tags inside a single group when only a few values differ.

**Rotating a leaked key without editing plaintext over SSH**  
Someone pasted a key in a PR comment. With a plain `.env` you're editing files and praying. With EnvSeal:

```bash
envseal set --tag prod STRIPE_SECRET
```

The update is encrypted in place. No plaintext ever hits disk.

## Key Features

- **Local & Global Vaults** — Git-committable `.envseal` files bound to a project, or a system-wide vault for personal scripts.

- **Multi-Profile Storage** — Isolated files such as `.prod.envseal` via the `--env` flag.

- **Protected Tags** — Share the main vault for development keys; lock high-stakes variables behind a completely separate secondary password.

- **Session Management** — Passwords cached in the OS keyring (Keychain, Secret Service, Windows Credential Manager) for 10 minutes.

- **CI/CD Automation** — Fully non-interactive via `ENVSEAL_PASSWORD` and `ENVSEAL_TAG_PASSWORD_<TAG>`.

- **Tamper Detection** — Every vault is HMAC-signed. Unauthorized edits are rejected on load.

- **Cross-Platform** — Linux, macOS, and Windows.

## Installation

**One-liner (recommended):**

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

The installer detects your platform, downloads the matching binary, places it in `~/.local/bin`, adds the directory to your PATH, and installs a small shell helper so `envseal load` works without manual `eval`. Supported shells include bash, zsh, and fish.

**Install a specific version or from a local binary:**

```bash
# Specific release
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash -s -- --version v2.0.1

# From a locally built binary (handy for development)
./scripts/install.sh --file ./target/release/envseal
```

**From source (manual):**

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build --release
./scripts/install.sh --file ./target/release/envseal
```

Pre-built binaries for Linux (x86_64/ARM64), macOS (Intel/Apple Silicon), and Windows are available on the [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) page.

## Quick Start

### Local Project Workflow (Recommended for Teams)

```bash
# 1. Initialize a local project vault
envseal init --local

# 2. Store development secrets
envseal set DATABASE_URL
envseal set API_KEY

# 3. Create a protected tag for sensitive environments
envseal protag prod
envseal set --tag prod STRIPE_SECRET

# 4. Run with secrets injected, then forgotten
envseal run npm start
envseal run --tag prod npm start

# 5. Clear the keyring session when stepping away
envseal clear
```

### Global Vault Workflow (Personal Scripts)

```bash
envseal --global init
envseal --global link myapp
envseal --global set AWS_ACCESS_KEY
envseal --global run ./deploy.sh
```

### Multi-Profile Environments

Prefer physical file separation over tags?

```bash
envseal -e staging init --local
envseal -e staging set API_URL
envseal -e staging run npm start
```

## Commands

| Command | Description |
|---|---|
| `envseal init [--local]` | Creates the encrypted vault and sets the master password. |
| `envseal set [-g GROUP] [-t TAG] KEY` | Sets or updates a key. |
| `envseal get [-g GROUP] [-t TAG] KEY` | Retrieves a single secret to stdout. |
| `envseal protag [-g GROUP] TAG` | Creates a protected tag requiring a secondary password. |
| `envseal import [-g GROUP] [-t TAG] PATH` | Bulk-imports an existing plaintext `.env` file. |
| `envseal export [-g GROUP] [-t TAG] [KEYS]` | Decrypts secrets back to standard `.env` format. |
| `envseal run [-g GROUP] [-t TAG] -- CMD` | Runs `CMD` with secrets injected into that process only. |
| `envseal list [-g GROUP] [-t TAG]` | Lists key names (never values). |
| `envseal remove [-g GROUP] [-t TAG] [KEY]` | Deletes a key, tag, or entire group. |
| `envseal link GROUP` | (Global only) Binds a global group to the current directory. |
| `envseal clear` | Flushes active master and tag passwords from the OS keyring. |
| `envseal load [-g GROUP] [-t TAG] [KEYS]` | Outputs shell-compatible export commands (prefer `run`). |

**Global flags:**

- `-G, --global` — Force operations on the global system vault.

- `-e, --env <NAME>` — Target a specific local environment profile (e.g. `-e prod` → `.prod.envseal`).

## Why Not Just Use `.env`?

A `.env` file is just a text file, and text files have a way of ending up places they shouldn't. EnvSeal gives you:

- **Safe to commit** — A `.envseal` file without the master password is useless ciphertext. (Do not commit vaults that contain production secrets if every developer knows the master password.)

- **Scoped exposure** — Sourcing a `.env` exposes secrets to every process you own. `envseal run` restricts them to the specific execution tree.

- **Zero-trust collaboration** — Protected tags let junior developers unlock development secrets while remaining cryptographically locked out of production.

- **Cryptographic integrity** — HMAC signing ensures a manually altered vault is rejected on load.

## Security Model

- **Encryption**: AES-256-GCM (authenticated encryption, fresh nonce every time).

- **Key Derivation**: Argon2, tuned to be memory-hard and resistant to GPU brute-forcing.

- **Integrity**: HMAC-SHA256 signature validation on every load.

- **Memory Handling**: Secrets are securely wiped after use via Rust's `zeroize` crate.

- **Session Caching**: Native OS keyring (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows) for 10-minute sessions.

- **No Password Recovery**: Lose the password and the vault is permanently unrecoverable. This is actual security, not security theater.

## Best Practices

- Prefer `run` over `load`. `load` dumps secrets into your live shell; `run` injects them ephemerally.
- In CI/CD, set `ENVSEAL_PASSWORD` (and `ENVSEAL_TAG_PASSWORD_<TAG>` when needed) to skip interactive prompts.
- Run `envseal clear` when stepping away from the machine.
- Keep production behind protected tags or separate profiles and share those passwords narrowly.

## Troubleshooting

**"Seal already exists"**  
You're trying to `init` in a directory that already has a `.envseal` file, or the global vault is already set up.

**"No group linked to current directory"**  
If using the global vault, run `envseal --global link <groupname>` first.

**"SEAL TAMPERED: HMAC verification failed"**  
The file was manually edited or corrupted. Restore from backup or re-import from source.

**Repeated password prompts / keyring issues**  
Ensure the OS keyring service is running, or run `envseal clear` to reset the session.

## Contributing

Fork it, branch it, fix something, open a PR. Bug reports, platform testing (especially Windows), and security audits are all welcome.

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build
cargo test
cargo fmt
cargo clippy
```

## License

MIT. Use it, fork it, ship it — just keep the license notice, and never put your master password in a pull request.