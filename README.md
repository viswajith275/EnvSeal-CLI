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

[Quick Start](#quick-start) · [Installation](#installation) · [Commands](#commands) · [Why EnvSeal](#why-this-exists) · [Features](#what-you-get) · [Troubleshooting](#troubleshooting) · [Uninstall](#uninstall)

---

## Quick Start

### 1. Local Project (Teams)

```bash
# 1. Initialize a local vault (.envseal file safe to commit)
envseal init --local

# 2. Store development secrets (no more plaintext .env files)
envseal set DATABASE_URL
envseal set API_KEY

# 3. Lock production keys behind a second password (so junior devs don't accidentally drop prod)
envseal protag prod
envseal set --tag prod STRIPE_SECRET

# 4. Run your app (secrets exist ONLY for the duration of this command)
envseal run npm start
envseal run --tag prod npm start

# 5. Lock up when stepping away for coffee
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
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash -s -- --version v5.0.0

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
| `envseal init [--local]` | Create a new encrypted vault. |
| `envseal set [-g GROUP] [-t TAG] KEY` | Store or update a secret. |
| `envseal get [-g GROUP] [-t TAG] [--token-file PATH] KEY` | Print a single decrypted value. |
| `envseal protag [-g GROUP] TAG` | Create a protected tag requiring a secondary password. |
| `envseal passwd` | Change the vault master password (derives a fresh KEK and signing key, then re-encrypts the Master DEK without modifying secret entries). |
| `envseal import [-g GROUP] [-t TAG] PATH` | Import a plaintext `.env` file into the vault (and safely delete the plaintext file). |
| `envseal export [-g GROUP] [-t TAG] [--token-file PATH] [-o PATH] [KEYS...]` | Export secrets back to a `.env` file (if you must). |
| `envseal run [-g GROUP] [-t TAG] [--token-file PATH] -- CMD` | Run a command with secrets injected exclusively into that process tree. |
| `envseal load [-g GROUP] [-t TAG] [--token-file PATH] [KEYS...]` | Output shell export statements (useful for legacy setups, though `run` is preferred). |
| `envseal list [-g GROUP] [-t TAG]` | List stored key names (values remain hidden). |
| `envseal remove [-g GROUP] [-t TAG] [KEY]` | Delete a specific key, tag, or group. |
| `envseal link GROUP` | Bind a global vault group to the current working directory. |
| `envseal clear` | Flush cached session keys from the OS keyring cache. |
| `envseal token [-g GROUP] [-t TAG] [-n NAME] [-d DESC] [-o PATH] [--exp SECS] [KEYS...]` | Mint a scoped zero-trust bearer token. |
| `envseal rotate [-g GROUP] [-t TAG]` | Rotate the DEK for a scope and invalidate all existing tokens instantly. |

### Global Flags

| Flag | Description |
| --- | --- |
| `-e, --env <NAME>` | Target a specific profile (e.g., `-e prod` reads/writes `.prod.envseal`). |
| `-G, --global` | Target the global system vault instead of the local directory vault. |

---

## Why This Exists

Plaintext secrets have a habit of multiplying: copied into scripts, pasted into chats, and leaked to Git scrapers within 30 seconds of an accidental push.

EnvSeal keeps the dead-simple ergonomics of `.env` files while giving you real cryptographic protection without forcing you into expensive cloud platforms.

| Feature | `.env` files | dotenvx | SOPS | **EnvSeal** | Doppler |
|---|---|---|---|---|---|
| Cross-platform (macOS/Linux/Windows) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Encrypted at rest | ❌ Plaintext | ✅ | ✅ | ✅ | ✅ |
| Works offline | ✅ | ✅ | ✅ | ✅ | ❌ |
| Requires cloud account | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Yes |
| Local-first | ✅ | ✅ | ✅ | ✅ | ❌ |
| Protected tags (second password for sensitive scopes) | ❌ | ❌ | ❌ | ✅ | ❌ |
| Zero-trust scoped bearer tokens | ❌ | ❌ | ❌ | ✅ | — |
| Instant token revocation via DEK rotation | ❌ | ❌ | ❌ | ✅ | — |

---

## What You Get

* **Local & Global Vaults**: Store project-specific variables in a commit-safe .envseal file, or manage system-wide utility tokens for personal CLI scripts in a centralized global vault.

* **Protected Tags**: Compartmentalize secrets within a single vault. Standard dev keys open with your master password; high-stakes tags (like prod or billing) stay locked behind independent secondary passwords.

* **Zero-Trust Bearer Tokens**: Mint least-privilege tokens scoped to a single tag or an explicit whitelist of keys. Tokens compress via zstd, embed strict issuance/expiration claims (iat/exp), and carry zero master key material.

* **Instant DEK Rotation**: envseal rotate generates a fresh Data Encryption Key for any scope and re-encrypts all underlying entries in place, instantly invalidating every token ever minted for that scope.
Battle-Tested Cryptographic Hierarchy: Master Password → Argon2id → Key Encryption Key (KEK) → Master DEK → HKDF-derived Scope DEKs → Per-entry AES-GCM / ChaCha20-Poly1305 Keys. Vault integrity and state transitions are authenticated via Ed25519 signatures.

* **In-Memory Zeroization**: Decrypted secrets never linger in RAM. All core cryptographic buffers and secret payloads implement strict Zeroize / ZeroizeOnDrop routines upon allocation teardown.

* **OS Keyring Session Caching**: Derived cryptographic keys (never your raw master password) cache securely in your OS keyring for 10 minutes, cutting subsequent CLI response latency to single-digit milliseconds.

* **Zero Cloud Dependencies & Cross-Platform**: 100% offline, local-first engine with first-class pre-built binaries for macOS (Apple Silicon), Linux, and Windows.

---

## Core Security Architecture

* **Local & Global Vaults**: Encrypted `.envseal` files are completely safe to commit to version control. Global vaults manage personal keys for one-off CLI tools.

* **Protected Tags**: Keep staging and production keys inside the same file without giving everyone production access. Production tags require their own independent password.

* **Zero-Trust Bearer Tokens**: Generate scoped access tokens for CI/CD runners. Tokens carry zero master password or key-encryption-key data and only decrypt their scoped keys.

* **Master Password Changes**: `envseal passwd` rotates the vault's Key Encryption Key (KEK) and signing key, re-encrypting the Master DEK in place without requiring individual secrets to be touched.

* **Instant Revocation**: `envseal rotate` generates a new Data Encryption Key (DEK) for a specific scope, re-encrypts its secrets, and instantly invalidates every token ever minted for that scope.

* **Cryptographic Hierarchy**: Master password -> Argon2id -> KEK -> Master DEK -> HKDF-derived Scope DEKs -> per-variable Entry Keys. Vault mutations are authenticated via Ed25519 signatures.

* **Zero Memory Residue**: Sensitive memory buffers implement `Zeroize` / `ZeroizeOnDrop` so decrypted secrets do not linger in RAM.

* **Fast Session Cache**: Derived cryptographic keys (never your plaintext password) are cached in your OS keyring for ~10 minutes, making subsequent commands instant.

---

## Token Ingestion (CI/CD)

Passing secrets as command-line arguments is an invitation for `ps aux` to broadcast your keys to the world. EnvSeal ensures tokens are ingested safely:

| Method | Syntax | Recommended For |
| --- | --- | --- |
| **Token File** | `--token-file /path/to/.token` | Kubernetes secrets, Docker volumes |
| **Environment Variable** | `ENVSEAL_TOKEN` or `ENVSEAL_TOKEN_FILE` | GitHub Actions, GitLab CI |
| **Stdin** | `cat .token | envseal run ...` | Shell pipes and automated deploy scripts |

> **Security Note:** Token expiration (`--exp`) is a convenience, not a panic button. If a token is compromised:
> 1. Run `envseal rotate --tag <TAG>` to immediately break the old token.
> 2. Rotate the actual third-party credentials (database passwords, API keys) that were exposed.
> 
> 

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

```bash
function envseal
    if test "$argv[1]" = "load"
        if contains -- --help $argv; or contains -- -h$argv
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

    if ($EnvsealArgs.Count -gt 0 -and$EnvsealArgs[0] -eq 'load') {
        if ($EnvsealArgs -contains '--help' -or$EnvsealArgs -contains '-h') {
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
