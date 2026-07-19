# EnvSeal

**An encrypted vault for your API keys and secrets, because `.env` files have never once kept a secret.**

EnvSeal keeps your credentials organized into groups (`dev`, `staging`, `prod`, whatever) and locks them up with AES-256-GCM encryption. Within a group, you can go a level further with tags — so `myapp` can hold a `dev` tag and a `prod` tag without needing two separate groups cluttering things up. No more plaintext `.env` files sitting around waiting for a stray `git add .` to ruin your week.

---

## The Problem

- **Plaintext secrets everywhere.** `.env` files get committed, copied, and forgotten in `~/Downloads` next to a file called `final_final_v2.env`.
- **`.env` files pushed straight to GitHub.** It happens constantly: someone forgets `.env` is in `.gitignore`, force-adds it "just this once," or clones a repo that never had a `.gitignore` to begin with. The moment it's pushed, it's public — GitHub's history keeps it forever even if you delete it in the next commit, bots scrape new public commits for exposed keys within minutes, and now you're rotating every credential in that file at 2 a.m. instead of sleeping.
- **Environment mix-ups.** One misplaced key and your dev script is suddenly emailing real customers.
- **Global shell pollution.** Source a `.env` into your shell and now every background process, cron job, and nosy subshell can read your Stripe key.
- **No audit trail.** A secret leaks and nobody can say which script touched it — the digital equivalent of "it wasn't me."

## The Solution

EnvSeal encrypts everything at rest, organizes secrets into groups, and — most importantly — injects them only into the one process that needs them via `envseal run`. Your parent shell stays clean. Think of it as a bouncer for your environment variables: it checks ID, lets the right process in, and remembers nothing afterward.

---

## Installation

**One-liner (recommended):**

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

**From source:**

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build --release
mkdir -p ~/.local/bin
cp target/release/envseal ~/.local/bin/envseal
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
envseal --version
```

**Pre-built binaries:** grab one from [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) for Linux (x86_64/ARM64) or macOS (Intel/Apple Silicon).

---

## Quick Start

```bash
# 1. Create your vault (pick a master password you won't forget —
#    there is no "forgot password" link here, this isn't your bank)
envseal init

# 2. Store some secrets
envseal set --group dev DATABASE_URL
envseal set --group dev API_KEY

# 3. Or import an existing .env file wholesale
envseal import --group prod ~/.env.production

# 4. Use tags to split a group without multiplying groups
envseal set --group myapp --tag dev API_ENDPOINT
envseal set --group myapp --tag prod API_ENDPOINT

# 5. Run your app with secrets injected, then forgotten
envseal run --group dev npm start
envseal run --group myapp --tag prod npm start
```

Tags are handy when "dev" and "prod" are really the same app with a couple of values that differ — no need to spin up a whole extra group just to swap one endpoint.

That last step is the whole point: `npm start` gets the variables it needs, and the moment it exits, EnvSeal wipes them from memory. Your terminal history stays boring, exactly how history should be.

---

## Commands

| Command | What it does |
|---|---|
| `envseal init` | Creates the encrypted vault and sets your master password |
| `envseal set [-g GROUP] [-t TAG] KEY` | Sets or updates a key (creates the group if needed) |
| `envseal get [-g GROUP] [-t TAG] KEY` | Retrieves a single secret |
| `envseal import [-g GROUP] [-t TAG] PATH` | Bulk-imports a `.env` file |
| `envseal export [-g GROUP] [-t TAG] [KEYS...]` | Decrypts a group (or specific keys) back to `.env` format |
| `envseal load [-g GROUP] [-t TAG] [KEYS...]` | Loads keys into your *current* shell — convenient, but see below |
| `envseal run [-g GROUP] [-t TAG] -- CMD` | Runs `CMD` with secrets injected into that process only (recommended) |
| `envseal list [-g GROUP] [-t TAG]` | Lists keys in a group or tag |
| `envseal remove [-g GROUP] [-t TAG] [KEY]` | Deletes a key, or the whole group if no key is given |
| `envseal link GROUP` | Binds a group to the current directory, so you stop typing `--group` fifty times a day |

**Prefer `run` over `load`.** `load` dumps secrets into your live shell session, where they'll happily outlive their usefulness and show up in `env` output during a screen share. `run` hands secrets to one process and then pretends it never met them.

```bash
# Fine, but leaves secrets sitting in your shell
eval "$(envseal load --group dev)"
npm start

# Better: secrets exist only for as long as npm needs them
envseal run --group dev npm start
```

---

## Why Not Just Use `.env` in Production

Because a `.env` file is just a text file that happens to hold your database password, and text files have a way of ending up places they shouldn't. Compared to a raw `.env` in production, EnvSeal gives you:

- **Nothing readable at rest.** A leaked `.env` is instantly usable by whoever finds it. A leaked vault file is a wall of ciphertext they'd need your master password to do anything with.
- **No `.env` to accidentally `git add`.** If the secrets never exist as plaintext on disk, they can't be committed, `scp`'d, or grabbed by a misconfigured backup script.
- **Scoped exposure instead of global exposure.** A `.env` sourced into your shell or loaded by your process manager is readable by anything else running as that user. `envseal run` hands secrets to exactly one process for exactly as long as it runs.
- **One vault, many environments.** Instead of `.env`, `.env.staging`, `.env.production`, and the inevitable confusion about which one is loaded, you get named groups you switch between on purpose.
- **A real audit habit.** `envseal list` and `envseal export` give you a deliberate way to check what's live in a given environment, rather than grepping through a file you hope is current.
- **Rotation without dread.** `envseal set` updates a key in place, encrypted the whole time — no editing a plaintext file over SSH and hoping you don't fat-finger a production credential.

None of this replaces a proper secrets manager for a large team running infrastructure at scale — EnvSeal is upfront about that. But it's a large step up from "production's secrets live in a text file called `.env` on a server somewhere."

---

## Security Model

- **Encryption:** AES-256-GCM (authenticated encryption, fresh nonce every time)
- **Key derivation:** Argon2, tuned to be memory-hard so GPUs don't have an easy time of it
- **Memory handling:** secrets are zeroized after use, courtesy of Rust's `zeroize` crate
- **No password recovery, on purpose.** If EnvSeal could recover your master password, so could someone else. Lose it and you're re-importing from source files — annoying, but that's the deal with actual security instead of security theater.

**What EnvSeal protects against:** disk breaches, accidental commits, shell-history leaks, memory dumps, brute-force and dictionary attacks, replay attacks.

**What it can't protect against:** malware already running on your machine, someone standing behind you reading your screen, or you texting your master password to a coworker "just this once."

---

## Best Practices

- Use `envseal run`, not `envseal load`, as your default
- Use a real passphrase, not `password123!` with the exclamation point doing all the security work
- Back up your vault file — encrypted backups are still encrypted, so there's no downside
- Never commit the vault file or any `.env` file to git; EnvSeal is the replacement, not a supplement
- Use different master passwords per machine, so one laptop theft doesn't become a full-portfolio breach

---

## Troubleshooting

**"no vault found"** — you haven't run `envseal init` yet. Everyone forgets this once.

**"no entry / group named X"** — groups and keys are case-sensitive. Check with `envseal list --group X`.

**`load` isn't setting variables** — the shell hook didn't install. Use `eval "$(envseal load --group dev)"` directly, or re-run the installer and re-source your shell config.

**Vault won't open / looks corrupted** — restore from backup if you have one. If not, delete the vault, `envseal init` again, and re-import from your original `.env` files. This is exactly why "Back up your vault" is on the best-practices list and not just there for decoration.

**Forgot the master password** — see "no password recovery" above. Re-import from source files with a new vault. Painful once; a good reminder to write the password down somewhere sane forever after.

---

## Contributing

Fork it, branch it, fix something, open a PR. Bug reports, platform testing, and security audits are all welcome — the last one especially, since "trust me, it's fine" isn't a security model.

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

MIT. Use it, fork it, ship it — just keep the license notice, and maybe don't put your master password in the pull request.
