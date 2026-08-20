# EnvSeal
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

We have all lived the classic developer horror story:

* **The 3 AM Hackathon Push:** You run `git add .`, push your semester project to a public GitHub repo, and wake up to 14 automated emails from AWS warning you that a bot in Frankfurt just racked up $3,400 mining crypto on your free-tier account.

* **The "Organized" Solo Dev:** Your directory is a digital graveyard of `.env.local`, `.env.prod.bak`, `.env.FINAL.REAL`, and `.env.DO_NOT_DELETE_OR_SERVER_DIES`.

* **The Group Project Strategy:** Passing around the live MongoDB connection string with `admin:password123` via Discord DMs followed by *"please delete this message after copying."*

EnvSeal ends this chaos. It is a local-first, zero-trust secrets engine built for solo tinkerers, student hackers, and distributed teams. Your secrets remain encrypted at rest in a commit-safe `.envseal` file, are injected **exclusively** into the memory of child processes at runtime, and never touch your shell history, environment leaks, or Git trees.

[Quick Start](#quick-start) · [Installation](#installation) · [Commands](#commands) · [Why EnvSeal](#why-this-exists) · [Features](#what-you-get) · [Git Merge Conflict Strategies](#git-merge-conflict-strategies) · [Troubleshooting](#troubleshooting) · [Uninstall](#uninstall)

---

## Quick Start

### 1. Local Project (Teams)

```bash
# 1. Initialize a local vault (.envseal file safe to commit)
envseal init --local

# 2. (Optional) Configure Git merge/diff drivers so seals merge cleanly
envseal git-setup

# 3. Store development secrets (no more plaintext .env files)
envseal set DATABASE_URL
envseal set API_KEY

# 4. Lock production keys behind a second password (so junior devs don't accidentally drop prod)
envseal protag prod
envseal set --tag prod STRIPE_SECRET

# 5. Run your app (secrets exist ONLY for the duration of this command)
envseal run npm start
envseal run --tag prod npm start

# 6. Lock up when stepping away for coffee
envseal clear
```

### 2. Global Vault (Personal Scripts & One-Offs)

```bash
envseal --global init
envseal --global link myapp
envseal --global set AWS_ACCESS_KEY
envseal --global run ./deploy.sh
```

### 3. Multi-Profile Environments

```bash
# For when 'staging' and 'production' need completely different universes
envseal -e staging init --local
envseal -e staging set API_URL
envseal -e staging run npm start
```

### 4. CI/CD with Scoped Tokens

```bash
# Mint a scoped token on your machine (never put the master password in GitHub Actions!)
envseal token -t prod -o ./.token --exp 7200 -n "ci-prod" -d "GitHub Actions deploy"

# In your pipeline runner
export ENVSEAL_TOKEN_FILE=./.token
envseal run --tag prod --token-file ./.token npm run migrate

# Or pipe it straight in via stdin
cat .token | envseal run --tag prod npm start
```

---

## Installation

### Windows (WinGet)

```bash
winget install --id viswajith275.envseal -e
```

### Linux & macOS

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

*Prefer to inspect the script before running it? Download and review it first:*

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh -o install.sh
less install.sh
bash install.sh
```

### Other Installation Options

**Specific Version**

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash -s -- --version v5.1.0
```

**From a Local Binary**

```bash
./scripts/install.sh --file ./target/release/envseal
```

**Build From Source**

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build --release
./scripts/install.sh --file ./target/release/envseal
```

---

## Commands

| Command | Description |
| --- | --- |
| `envseal init [--local] [--git]` | Create a new encrypted vault. Optionally initialize a Git repository. |
| `envseal git-setup [--init]` | Configure Git merge and diff drivers for `.envseal` files. |
| `envseal set [-g GROUP] [-t TAG] KEY` | Store or update a secret. |
| `envseal get [-g GROUP] [-t TAG] [--token-file PATH] KEY` | Print a single decrypted value. |
| `envseal protag [-g GROUP] TAG` | Create a protected tag requiring a secondary password. |
| `envseal passwd` | Change the vault master password (derives a fresh KEK and signing key, then re-encrypts the Master DEK without modifying secret entries). Does **not** invalidate existing tokens. |
| `envseal import [-g GROUP] [-t TAG] PATH` | Import a plaintext `.env` file into the vault (and safely delete the plaintext file). |
| `envseal export [-g GROUP] [-t TAG] [--token-file PATH] [-o PATH] [KEYS...]` | Export secrets back to a `.env` file (if you must). |
| `envseal run [-g GROUP] [-t TAG] [--token-file PATH] -- CMD` | Run a command with secrets injected exclusively into that process tree. Alias: `exec`. |
| `envseal load [-g GROUP] [-t TAG] [--token-file PATH] [KEYS...]` | Output shell export statements (useful for legacy setups; prefer `run` when possible). |
| `envseal list [-g GROUP] [-t TAG]` | List stored key names (values remain hidden). Alias: `ls`. |
| `envseal remove [-g GROUP] [-t TAG] [KEY]` | Delete a specific key, tag, or group. Alias: `rm`. |
| `envseal link GROUP` | Bind a global vault group to the current working directory. |
| `envseal clear` | Flush cached session keys from the OS keyring cache. |
| `envseal token [-g GROUP] [-t TAG] [-n NAME] [-d DESC] [-o PATH] [--exp SECS] [KEYS...]` | Mint a scoped zero-trust bearer token. |
| `envseal rotate [-g GROUP] [-t TAG]` | Rotate the DEK for a scope and invalidate all existing tokens instantly. |

### Global Flags

| Flag | Description |
| --- | --- |
| `-e, --env <PROFILE>` | Target a specific profile (e.g., `-e prod` reads/writes `.prod.envseal`). |
| `-G, --global` | Target the global system vault instead of the local directory vault. |
| `--no-env` | Disable loading fallback passwords from environment variables. |

---

## Why This Exists

Plaintext secrets have a habit of multiplying: copied into scripts, pasted into chats, and leaked to Git scrapers within 30 seconds of an accidental push.

EnvSeal keeps the dead-simple ergonomics of `.env` files while giving you real cryptographic protection without forcing you into expensive cloud platforms.

When deciding how to manage environment variables and secrets, there is a wide spectrum of tools—from plain text files to full-blown SaaS platforms.

The table below breaks down the most popular approaches based on their security models, developer experience (DX), and Git compatibility.

| Aspect | Plain `.env` | dotenvx | SOPS | EnvSeal | Doppler |
| --- | --- | --- | --- | --- | --- |
| **Core idea** | Plaintext files | Encrypt classic `.env` files so you can commit them | Encrypt values inside structured files (YAML/JSON/ENV) while keeping keys readable | Local encrypted vault with scopes, tokens & Git drivers | Full SaaS secrets platform |
| **Encryption model** | None | Public-key (x25519 / ECIES) per file | age / cloud KMS / PGP | Password → Argon2id → KEK → DEK hierarchy + Ed25519 | Server-side (Doppler holds the keys) |
| **Offline / local-first** | Yes | Yes | Yes | **Yes** | No (requires network) |
| **Safe to commit to Git** | Never | Yes (encrypted values) | Yes (values encrypted, keys visible) | **Yes (opaque encrypted vault)** | Secrets never touch Git |
| **Git merge / diff support** | Native text | None (treat as normal text) | Official cleartext diff; merge needs community scripts | **First-party merge + diff drivers + `fail`/`ours`/`theirs` strategies** | N/A |
| **Access control** | None | None (anyone with the private key sees everything) | Key recipients / KMS policies | **Master password + optional protected tags (second password)** | RBAC, roles, service tokens, SSO |
| **CI / short-lived access** | Env vars / secrets in the CI system | Private key as env var | Private key or KMS credentials | **Scoped zero-trust bearer tokens (expiring, least-privilege, instantly revocable via DEK rotation)** | Service tokens / OIDC |
| **Multi-environment** | Multiple files (`.env.prod`, etc.) | Multiple encrypted files | Multiple files or paths | **Profiles (`-e`) + tags** | First-class environments & configs |
| **Audit / rotation UX** | None | Manual re-encrypt | Manual key rotation | **Instant DEK rotation invalidates all tokens for a scope** | Built-in rotation, versioning, activity logs |
| **Learning curve** | Zero | Very low (feels like dotenv) | Medium–high (especially with KMS) | **Low–medium** | Low (excellent DX) |

### Summary

The landscape of secrets management forces a choice between **convenience**, **security**, and **cloud reliance**.

* **Plain `.env` files** are convenient but offer zero security.

* **SaaS solutions (like Doppler)** offer great features but tie your application to an external network and a recurring subscription.

* **Git-based encryption (dotenvx, SOPS, EnvSeal)** bridges the gap, allowing you to use Git as your single source of truth without exposing sensitive data. However, dealing with encrypted files in Git usually introduces massive headaches around merge conflicts and access revocation.

### Which tool should you use?

**Choose `EnvSeal` if... (The Sweet Spot)**
You want enterprise-grade security without the overhead of a SaaS platform. EnvSeal hits the perfect middle ground for modern development teams. It keeps everything local-first and self-contained in your repository, but completely eliminates the usual encrypted-Git headaches by providing **native Git diff/merge drivers**. Furthermore, its zero-trust expiring CI tokens mean you never have to blindly paste long-lived master keys into your CI/CD pipeline.

**Choose `dotenvx` if...**
You are a solo developer or a very small team looking for the absolute fastest way to stop committing plain `.env` files. It's a great stepping stone, though you will likely outgrow it once you start running into Git merge conflicts on encrypted strings or need granular access control for different team members.

**Choose `SOPS` if...**
You are working heavily in Kubernetes, GitOps, or large-scale infrastructure-as-code, and you already rely heavily on cloud provider KMS (AWS KMS, GCP KMS). It's the industry standard for infrastructure, though the developer experience and setup curve can be steep for standard app development.

**Choose `Doppler` if...**
You have the budget for a SaaS platform, need strict enterprise compliance (SOC2, detailed audit logs), and don't mind your app requiring a network connection to fetch its configuration on startup.

**Choose `Plain .env` if...**
You are building a temporary weekend hackathon project or a local-only prototype with zero real API keys. *(Note: Never commit these to Git!)*

---

## What You Get

* **Local & Global Vaults**: Store project-specific variables in a commit-safe `.envseal` file, or manage system-wide utility tokens for personal CLI scripts in a centralized global vault.

* **Protected Tags**: Compartmentalize secrets within a single vault. Standard dev keys open with your master password; high-stakes tags (like `prod` or `billing`) stay locked behind independent secondary passwords.

* **Zero-Trust Bearer Tokens**: Mint least-privilege tokens scoped to a single tag or an explicit whitelist of keys. Tokens compress via zstd, embed strict issuance/expiration claims (`iat`/`exp`), and carry zero master key material.

* **Instant DEK Rotation**: `envseal rotate` generates a fresh Data Encryption Key for any scope and re-encrypts all underlying entries in place, instantly invalidating every token ever minted for that scope.

* **Battle-Tested Cryptographic Hierarchy**: Master Password → Argon2id → Key Encryption Key (KEK) → Master DEK → HKDF-derived Scope DEKs → Per-entry AES-GCM Keys. Vault integrity and state transitions are authenticated via Ed25519 signatures.

* **In-Memory Zeroization**: Decrypted secrets never linger in RAM. All core cryptographic buffers and secret payloads implement strict `Zeroize` / `ZeroizeOnDrop` routines upon allocation teardown.

* **OS Keyring Session Caching**: Derived cryptographic keys (never your raw master password) cache securely in your OS keyring for ~10 minutes, cutting subsequent CLI response latency to single-digit milliseconds.

* **Native Git Integration**: Custom merge and diff drivers keep encrypted seals conflict-free in version control while still surfacing meaningful diffs when needed.

* **Zero Cloud Dependencies & Cross-Platform**: 100% offline, local-first engine with first-class pre-built binaries for macOS (Apple Silicon), Linux, and Windows.

---

## Core Security Architecture

* **Local & Global Vaults**: Encrypted `.envseal` files are completely safe to commit to version control. Global vaults manage personal keys for one-off CLI tools.

* **Protected Tags**: Keep staging and production keys inside the same file without giving everyone production access. Production tags require their own independent password.

* **Zero-Trust Bearer Tokens**: Generate scoped access tokens for CI/CD runners. Tokens carry zero master password or key-encryption-key data and only decrypt their scoped keys.

* **Master Password Changes**: `envseal passwd` rotates the vault's Key Encryption Key (KEK) and signing key, re-encrypting the Master DEK in place without requiring individual secrets to be touched.

* **Instant Revocation**: `envseal rotate` generates a new Data Encryption Key (DEK) for a specific scope, re-encrypts its secrets, and instantly invalidates every token ever minted for that scope.

* **Cryptographic Hierarchy**: Master password → Argon2id → KEK → Master DEK → HKDF-derived Scope DEKs → per-variable Entry Keys. Vault mutations are authenticated via Ed25519 signatures.

* **Zero Memory Residue**: Sensitive memory buffers implement `Zeroize` / `ZeroizeOnDrop` so decrypted secrets do not linger in RAM.

* **Fast Session Cache**: Derived cryptographic keys (never your plaintext password) are cached in your OS keyring for ~10 minutes, making subsequent commands instant.

---

## Token Ingestion (CI/CD)

Passing secrets as command-line arguments is an invitation for `ps aux` to broadcast your keys to the world. EnvSeal ensures tokens are ingested safely:

| Method | Syntax | Recommended For |
| --- | --- | --- |
| **Token File** | `--token-file /path/to/.token` | Kubernetes secrets, Docker volumes |
| **Environment Variable** | `ENVSEAL_TOKEN` or `ENVSEAL_TOKEN_FILE` | GitHub Actions, GitLab CI |
| **Stdin** | `cat .token \| envseal run ...` | Shell pipes and automated deploy scripts |

> **Security Note:** Token expiration (`--exp`) is a convenience, not a panic button. If a token is compromised:
> 1. Run `envseal rotate --tag <TAG>` to immediately break the old token.
> 2. Rotate the actual third-party credentials (database passwords, API keys) that were exposed.

---

## Git Merge-Conflict Strategies

Because EnvSeal integrates as a native Git merge driver, it runs invisibly in the background during a git pull, git merge, or git rebase. When two branches modify the exact same encrypted variable or tag, a cryptographic conflict occurs.

By default, EnvSeal uses a Fail-Safe approach and immediately halts the merge to prevent silent data loss. You can, however, explicitly override this behavior inline or configure a persistent repository-level strategy using git config.

### One-Off Resolution (Recommended)

If a merge halts due to a conflict, abort the merge and explicitly override the configuration for a single command using Git's -c flag.

Keep your local variables:

```bash
git merge --abort
git -c envseal.merge.strategy=ours merge feature-branch
```

Accept incoming variables:


```bash
git merge --abort
git -c envseal.merge.strategy=theirs merge feature-branch
```

### Repository-Level Default

To set a persistent merge strategy for your local repository so you don't have to use the -c flag, run:

```bash
git config envseal.merge.strategy <strategy>
```
### Available Strategies

> **fail (Default):** Halts the merge process immediately upon detecting a conflict. Best for strict local development. (To reset: git config --unset envseal.merge.strategy)

> **ours:**: If a conflict occurs, the variables in your current branch always win. Best for when you are actively rotating local keys.

> **theirs:**: If a conflict occurs, the variables from the incoming branch overwrite your local variables. Best for CI/CD runners or automated deployment servers pulling from main.

> **Tip:** Run `envseal git-setup` once per repository to register the custom merge and diff drivers. After that, the strategy above controls conflict resolution behaviour.

---

## Shell Integration (Optional)

`envseal run -- <CMD>` is the gold standard because secrets disappear the second the process exits. If you genuinely want to export variables into your active interactive shell session, add the wrapper below:

### Bash / Zsh (`~/.bashrc`, `~/.zshrc`)

```bash
envseal() {
    if [ "$1" = "load" ]; then
        for _arg in "$@"; do
            if [ "$_arg" = "--help" ] || [ "$_arg" = "-h" ]; then
                command envseal "$@"
                return
            fi
        done
        eval "$(command envseal "$@")"
    else
        command envseal "$@"
    fi
}
```

### Fish (`~/.config/fish/config.fish`)

```fish
function envseal
    if test "$argv[1]" = "load"
        if contains -- --help $argv; or contains -- -h $argv
            command envseal $argv
        else
            eval (command envseal $argv)
        end
    else
        command envseal $argv
    end
end
```

### PowerShell (`$PROFILE`)

```powershell
function envseal {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$EnvsealArgs
    )

    $exe = Get-Command envseal -CommandType Application -ErrorAction SilentlyContinue |
           Select-Object -First 1 -ExpandProperty Source

    if (-not $exe) {
        Write-Error "envseal: not found on PATH. Install it with: winget install viswajith275.envseal"
        return
    }

    if ($EnvsealArgs.Count -gt 0 -and $EnvsealArgs[0] -eq 'load') {
        if ($EnvsealArgs -contains '--help' -or $EnvsealArgs -contains '-h') {
            & $exe @EnvsealArgs
            return
        }
        & $exe @EnvsealArgs | Invoke-Expression
    }
    else {
        & $exe @EnvsealArgs
    }
}
```

---

## Troubleshooting

* **"Seal already exists"**: You are trying to `init` where a vault already lives. Re-sealing an already sealed vault is very meta, but unnecessary. Use the existing vault or delete it to start fresh.

* **"No group linked to current directory"**: Run `envseal --global link <GROUP>` to associate this directory with your global vault group.

* **Signature / integrity verification failed**: The `.envseal` file was modified by an external editor or corrupted. Restore from git/backup or re-import.

* **Token decryption fails after a rotate**: Working as intended. When you rotate a DEK, older tokens become useless ciphertext. Mint a fresh token with `envseal token`.

* **Repeated password prompts**: Check if your OS keyring daemon is running. If it is stuck, run `envseal clear` to reset the session.

* **Git merge halted on conflict**: EnvSeal’s default strategy is `fail`. See [Repository-Level Merge Strategies](#repository-level-merge-strategies) to configure `ours` or `theirs` if automatic resolution is appropriate for your workflow.

---

## Upcoming

* **Local Proxy**: Credential injection into outbound HTTP/network traffic via a local proxy, preventing third-party packages or memory-dump exploits from ever seeing raw secrets in process memory.

---

## Contributing

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build
cargo test
cargo fmt
cargo clippy
```

---

## Uninstall

### Windows (WinGet)

```bash
winget uninstall --id viswajith275.envseal -e
```

### Linux & macOS

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/uninstall.sh | bash
```

---

## License

MIT
