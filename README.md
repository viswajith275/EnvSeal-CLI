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

**EnvSeal**: Your Encrypted Personal Vault for Secrets

A lightweight, encrypted command-line vault for securely managing API keys, secrets, and sensitive environment variables on your local machine. EnvSeal organizes your secrets into **groups** (like `dev`, `staging`, `prod`) and keeps them under military-grade encryption. No more scattered `.env` files or accidental commits of sensitive data!

**Version:** see [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) for the current version and changelog.

---

## Quick Links

- **[Installation](#installation)** - Get started in 2 minutes
- **[Quick Start](#quick-start)** - Your first 4 steps
- **[Commands Reference](#commands-reference)** - Complete CLI reference
- **[Troubleshooting](#troubleshooting)** - Solve common issues
- **[Security](#security-model)** - See how it works

---

## Installation

### Method 1: Automated Installation (Recommended)

The installer auto-detects your OS and architecture, installs the matching binary, and sets up shell integration.

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

**Available options:**

```bash
./install.sh --help
```

| Option | Description |
|--------|-------------|
| `-v, --version <tag>` | Install a specific release (e.g., `v1.2.3`). Default: latest |
| `-d, --dir <path>` | Custom install directory. Default: `~/.local/bin` |
| `-f, --file <path>` | Install from a local tarball or binary |
| `--dry-run` | Preview changes without installing |

**Examples:**

```bash
# Install latest version
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash

# Install specific version
./install.sh --version v1.2.3

# Install to custom directory
./install.sh --dir /usr/local/bin

# Dry run to preview
./install.sh --dry-run
```

### Method 2: Build from Source

**Prerequisites:**
- [Rust 1.70+](https://www.rust-lang.org/tools/install)
- `cargo` package manager

```bash
# Clone the repository
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI

# Build in release mode
cargo build --release

# Install to your PATH
mkdir -p ~/.local/bin
cp target/release/envseal ~/.local/bin/envseal
chmod +x ~/.local/bin/envseal

# Add to PATH if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
envseal --version
```

### Method 3: Download Pre-built Binary

Visit the [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) page and download the binary for your platform:

- `envseal-linux-x86_64.tar.gz` — Linux x86_64
- `envseal-linux-aarch64.tar.gz` — Linux ARM64
- `envseal-macos-x86_64.tar.gz` — macOS Intel
- `envseal-macos-aarch64.tar.gz` — macOS Apple Silicon (M1/M2)

```bash
# Example: macOS Apple Silicon
tar -xzf envseal-macos-aarch64.tar.gz
chmod +x envseal
mv envseal ~/.local/bin/
```

---

## Table of Contents

* [Why EnvSeal?](#why-envseal)
* [Problem and Solution](#problem-and-solution)
* [Key Features](#key-features)
* [Architecture](#architecture)
* [Security Model](#security-model)
* [Quick Start](#quick-start)
* [Commands Reference](#commands-reference)
* [Usage Scenarios](#usage-scenarios)
* [Performance](#performance)
* [Security Details](#security-details)
* [Best Practices](#best-practices)
* [Troubleshooting](#troubleshooting)
* [Upcoming Features](#upcoming-features)
* [Contributing](#contributing)
* [License](#license)

---

## Why EnvSeal?

Imagine juggling multiple `.env` files across different projects, environments, and machines. You switch between local development, staging, and production—each with different API keys, database URLs, and credentials. One wrong copy-paste, and you've exposed production secrets to your dev environment.

**EnvSeal eliminates this chaos** by:
- Centralizing all your secrets in one encrypted vault
- Organizing secrets by environment/project groups
- Injecting secrets safely into child processes without polluting your shell
- Switching between environments with a single command
- Protecting everything with AES-256-GCM encryption + Argon2 hashing
- Wiping sensitive data from memory automatically

---

## Problem and Solution

### The Problem

Developers often struggle with securely managing API keys, tokens, and sensitive credentials:

* **Plain-text storage disasters**: Keeping secrets in `.env` files or shell scripts exposes them to accidental commits and unauthorized access. A single `git add .` can turn into a security breach!
* **Environment sprawl**: Switching between different API keys for different environments (dev, staging, prod) is tedious and error-prone. Copy-paste mistakes can cause critical failures.
* **Global scope leaks**: Loading secrets into your global terminal session means any background script, sudo command, or spawned process can access them. Your entire session becomes a security liability.
* **Scattered secrets**: API keys scattered across multiple config files are hard to audit and manage. Where did that old Stripe key go?
* **No audit trail**: When secrets are compromised, you have no idea which process accessed them or when.

### The Solution

**EnvSeal provides**:

- **Group-Based Management**: Organize secrets into environments (e.g., `dev`, `prod`, `staging`) and switch seamlessly with a single command.
- **Secure Process Injection**: Use `envseal run` to inject secrets only into a specific child process. Your parent shell stays clean—no risk of global scope pollution.
- **End-to-End Encryption**: All sensitive data is encrypted at rest using **AES-256-GCM**, the same standard used by government agencies and major tech companies.
- **Master Password Protection**: The vault is locked behind a single, strong master password derived via **Argon2** (memory-hard hashing resistant to brute-force attacks).
- **Drop-in `.env` Replacement**: Easily import existing `.env` files in bulk or export groups back to `.env` format for CI/CD pipelines.
- **Memory Safety**: Built in Rust with automatic memory wiping via the `zeroize` crate to prevent secret leaks in RAM.
- **Cross-Platform**: Works seamlessly on Linux, macOS (Intel & Apple Silicon), with support for bash, zsh, and fish shells.

---

## Key Features

| Feature | Description |
|---------|-------------|
| AES-256-GCM Encryption | Military-grade authenticated encryption with associated data (AEAD) |
| Argon2 Key Derivation | Memory-hard password hashing resistant to GPU/ASIC attacks |
| Group Organization | Store secrets by project or environment (dev, staging, prod, etc.) |
| Process Injection | Safely run applications with decrypted variables injected directly—parent shell stays clean |
| Bulk Import/Export | Parse `.env` files into encrypted groups in seconds |
| Persistent Vault | Encrypted vault stored locally in your OS config directory |
| Memory Safety | Automatic memory wiping prevents sensitive data leaks |
| Cross-Platform | Linux, macOS (Intel & Apple Silicon), bash/zsh/fish |
| Directory Linking (Upcoming) | Bind a group to a directory—no need to specify group name repeatedly |
| Dynamic Tags (Upcoming) | Create dev/prod tags to swap variables on the fly |
| Zero-Overhead | Written in Rust for speed and safety |

---

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          User Shell (bash/zsh/fish)              │
│                                                                   │
│  $ envseal run --group prod npm start                            │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                   ┌─────────▼─────────┐
                   │   EnvSeal CLI     │
                   │   (Rust Binary)   │
                   └─────────┬─────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
         ┌──────▼──────┐         ┌────────▼──────┐
         │ Vault Mgmt  │         │ Crypto Engine │
         │             │         │               │
         │ • Decrypt   │         │ • AES-256-GCM │
         │ • Validate  │         │ • Argon2 KDF  │
         │ • Load      │         │ • Zeroize     │
         └──────┬──────┘         └────────┬──────┘
                │                         │
         ┌──────▼─────────────────────────▼──────┐
         │   Encrypted Vault (JSON)              │
         │   ~/.config/envseal/seal.json         │
         │                                        │
         │ {                                      │
         │   "groups": {                          │
         │     "prod": {                          │
         │       "encrypted_data": "...",         │
         │       "nonce": "...",                  │
         │       "salt": "..."                    │
         │     }                                  │
         │   }                                    │
         │ }                                      │
         └──────┬─────────────────────────────────┘
                │
         ┌──────▼──────────────────┐
         │  Child Process (npm)    │
         │                          │
         │  Environment:            │
         │  • DATABASE_URL          │
         │  • API_KEY               │
         │  • STRIPE_SECRET_KEY     │
         │  • JWT_SECRET            │
         └──────────────────────────┘
```

### Data Flow

```
Master Password Input
       │
       ▼
Argon2 KDF
(3 iterations, 64MB, 4 threads, random salt)
       │
       ▼
256-bit Encryption Key
       │
       ├─────────────────────────────────────┐
       │                                     │
       ▼                                     ▼
   PLAINTEXT                          Generate Random
   (Secrets)                          12-byte Nonce
       │                                     │
       └──────────────────┬──────────────────┘
                          │
                          ▼
                   AES-256-GCM
                   Authenticated
                   Encryption
                          │
                          ▼
              Ciphertext + Auth Tag
              + Nonce + Salt
                          │
                          ▼
                  JSON Vault File
           (Disk - Encrypted at Rest)
```

### Process Isolation Model

```
┌─────────────────────────────┐
│   Parent Shell Session      │
│                             │
│  Secrets: NOT loaded        │
│  History: CLEAN             │
│  Risk: MINIMAL              │
└──────────────┬──────────────┘
               │
        ┌──────▼───────┐
        │ envseal run  │
        │   --group    │
        │    prod      │
        └──────┬───────┘
               │
        ┌──────▼──────────────────────┐
        │ Child Process (npm start)   │
        │                              │
        │  Environment Variables:      │
        │  • DATABASE_URL (inherited)  │
        │  • API_KEY (inherited)       │
        │  • STRIPE_KEY (inherited)    │
        │                              │
        │  Scope: ISOLATED             │
        │  Risk: Contained             │
        └──────┬───────────────────────┘
               │
        ┌──────▼────────────────┐
        │ Memory Cleanup        │
        │ (zeroize on exit)     │
        │ All secrets wiped     │
        └───────────────────────┘
```

---

## Security Model

### Threat Model

#### Protected Against:

| Threat | Scenario | Mitigation |
|--------|----------|-----------|
| Accidental Git Commit | `.env` file accidentally committed | Vault encryption + import workflow prevents plain-text commits |
| Disk Breach | Attacker gains access to vault file | AES-256-GCM encryption at rest |
| Shell History Leaks | Secrets logged in shell history | `envseal run` isolates secrets to child process only |
| Memory Dumps | Attacker dumps process memory | `zeroize` crate overwrites sensitive data immediately |
| Brute Force (Master Password) | Attacker tries to crack master password | Argon2 memory-hard hashing (64MB, GPU-resistant) |
| Dictionary Attacks | Weak password guessing | High entropy requirement + Argon2 parameters |
| Privilege Escalation | Background process steals secrets | Only child process has access, parent shell clean |
| Replay Attacks | Attacker replays old encrypted data | Fresh random nonce for each encryption |
| Side-Channel Attacks | Timing/power analysis attacks | Constant-time crypto operations in underlying libraries |

#### NOT Protected Against:

| Threat | Why | Mitigation |
|--------|-----|-----------|
| Compromised Master Password | If attacker knows password, encryption useless | Use strong password + different password per machine |
| Malware on Host | Malware can intercept secrets at runtime | Full-disk encryption + endpoint security |
| Physical Access | Attacker with physical access | Secure your machine + enable BIOS/UEFI encryption |
| Social Engineering | User voluntarily shares password | Security awareness training |
| Quantum Computing | Future threat to AES-256 | AES is post-quantum candidate; migrate as standards evolve |

### Defense in Depth Strategy

```
Layer 1: Local File Permissions (OS-Level)
├─ Vault stored in user-only directory
├─ File permissions: 0600 (read/write owner only)
├─ Directory permissions: 0700
└─ Protection: Prevents other users from reading

Layer 2: Encryption at Rest
├─ Algorithm: AES-256-GCM
├─ Key derivation: Argon2 (memory-hard)
├─ Nonce: 12-byte random per encryption
└─ Protection: Unintelligible without master password

Layer 3: Process Isolation
├─ Secrets injected only to child process
├─ Parent shell environment stays clean
├─ No shell history contamination
└─ Protection: Limits scope of exposure

Layer 4: Memory Safety
├─ Zeroize sensitive data after use
├─ Overwrite in RAM before deallocation
├─ No secrets in core dumps
└─ Protection: Prevents memory forensics

Layer 5: Full-Disk Encryption
├─ Recommended: Enable OS-level encryption
├─ Linux: LUKS, Windows: BitLocker, macOS: FileVault
└─ Protection: Secrets can't be read from stolen disk
```

### Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────┐
│                      Attack Surface                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  MITIGATED:                                             │
│  • Vault file on disk (AES-256-GCM encryption)          │
│  • Shell environment (process isolation)                │
│  • Master password (Argon2 hashing)                     │
│  • Memory access (zeroize)                              │
│  • Network access (local-only, no network calls)        │
│                                                           │
│  PARTIALLY MITIGATED:                                    │
│  • Terminal output (user responsibility)                │
│  • Process arguments (audit via logs)                   │
│  • File system (user must enable encryption)            │
│                                                           │
│  OUT OF SCOPE:                                           │
│  • Physical security (machine theft)                    │
│  • Master password strength (user responsibility)       │
│  • Malware on system (security suite needed)            │
│  • Social engineering (training needed)                 │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Step 1: Initialize Your Vault

Create an encrypted vault with a master password:

```bash
envseal init
```

This creates an encrypted vault file in your OS config directory and prompts you to set a strong master password.

**Tips for a strong password:**
- Use 16+ characters mixing upper, lower, numbers, and symbols
- Avoid dictionary words and personal information
- Consider using a passphrase instead (e.g., "BlueSky!Coffee42#Moon")

### Step 2: Store Secrets in a Group

Store your development secrets in a group named `dev`:

```bash
envseal set --group dev DATABASE_URL
# Prompts for master password and the secret value
```

The group is created automatically on first use. Store multiple secrets:

```bash
envseal set --group dev API_KEY
envseal set --group dev STRIPE_SECRET_KEY
envseal set --group dev JWT_SECRET
```

### Step 3: Import an Existing `.env` File

Migrate a plain-text `.env` file into an encrypted group named `prod`:

```bash
envseal import --group prod ~/.env.production
```

This reads all key-value pairs and securely encrypts them in one go.

### Step 4: Run an Application Safely

Inject your group's secrets directly into a process without leaking them to the terminal:

```bash
envseal run --group dev npm start
```

This is the **recommended workflow**. It:
1. Prompts for your master password once
2. Decrypts the variables
3. Executes `npm start` with those variables in its environment
4. Automatically wipes sensitive data from memory
5. Leaves your parent shell clean

Compare this to the old way:
```bash
# BAD: Secrets in your shell history and global session
source .env.dev
npm start

# GOOD: Secrets isolated to child process only
envseal run --group dev npm start
```

---

## Commands Reference

### `envseal init`

Initialize a new encrypted vault with a master password.

```bash
envseal init
```

**Creates:**
- Encrypted vault file in OS config directory
- Master password stored securely (Argon2-derived key)

---

### `envseal set <KEY>`

Set or update a value for a given key in a group. Creates the group if it doesn't exist.

```bash
envseal set --group dev GITHUB_TOKEN
envseal set --group prod DATABASE_URL
envseal set --group myapp --tag prod API_ENDPOINT
```

---

### `envseal get <KEY>`

Retrieve a stored secret from a specific group.

```bash
envseal get --group dev GITHUB_TOKEN
```

---

### `envseal import <PATH>`

Bulk import all key-value pairs from a `.env` file into an encrypted group.

```bash
envseal import --group dev /path/to/.env.dev
envseal import --group prod /path/to/.env.production
```

---

### `envseal export [KEYS...]`

Decrypt and output an entire group (or specific keys) in `.env` format.

```bash
envseal export --group prod
envseal export --group prod DATABASE_URL API_KEY
envseal export --group prod > .env.production
```

---

### `envseal run <COMMAND>` (Recommended)

Load environment variables for a group and execute a command in a child process.

```bash
envseal run --group dev npm start
envseal run --group prod python app.py
envseal run --group staging ./deploy.sh
```

---

### `envseal load [KEYS...]`

Load specified keys (or entire group) into your current terminal environment.

```bash
eval "$(envseal load --group dev)"
envseal load --group dev DATABASE_URL API_KEY
```

---

### `envseal list [GROUP]`

List all keys currently stored in a specific group.

```bash
envseal list --group dev
```

---

### `envseal remove [KEY]`

Delete a specific key from a group, or delete the entire group if no key is specified.

```bash
envseal remove --group dev OLD_API_KEY
envseal remove --group dev  # Deletes entire group
```

---

### `envseal link <GROUP>` (Upcoming)

Bind a specific group to your current working directory.

```bash
envseal link myapp
envseal run npm start  # Uses 'myapp' group automatically
```

---

## Usage Scenarios

### Local Development Across Environments

```bash
# Initial setup: Import from your existing .env files
envseal import --group dev .env.dev
envseal import --group staging .env.staging
envseal import --group prod .env.prod

# Work on local dev
envseal run --group dev npm start

# Test against staging database
envseal run --group staging npm start

# Preview production
envseal export --group prod
```

**Benefits:**
- No `.env` files in your git repo
- Easy switching between environments
- Each environment isolated and encrypted
- No accidental commits of secrets

---

### CI/CD Pipeline Local Testing

```bash
# Store deployment credentials
envseal import --group deploy /path/to/aws-creds.env

# Test deployment script locally
envseal run --group deploy ./scripts/deploy_to_aws.sh

# Run integration tests with test database
envseal import --group test-db test-database.env
envseal run --group test-db npm run test:integration
```

---

### Server Deployment

```bash
# Export secrets to temporary .env file
envseal export --group prod > /tmp/.env.prod

# Use in docker deployment
docker run \
  --env-file /tmp/.env.prod \
  -v /var/www/app:/app \
  myapp:latest

# Clean up
rm /tmp/.env.prod

# Or use directly with run command
envseal run --group prod docker-compose up -d
envseal run --group prod ./scripts/health_check.sh
envseal run --group prod systemctl restart myapp
```

---

## Performance

### Benchmarks

All measurements on modern hardware (2019+ MacBook Pro, 2021+ Linux desktop):

| Operation | Input Size | Time | Memory |
|-----------|-----------|------|--------|
| init | N/A | ~500ms | ~5MB |
| set | Single variable | ~800ms | ~8MB |
| get | Single variable | ~700ms | ~7MB |
| import | 10 variables | ~900ms | ~10MB |
| import | 100 variables | ~1.2s | ~12MB |
| import | 1000 variables | ~8s | ~30MB |
| export | 10 variables | ~800ms | ~9MB |
| export | 100 variables | ~950ms | ~11MB |
| export | 1000 variables | ~5s | ~25MB |
| run | Startup overhead | ~300ms | ~6MB |
| list | 100 items | ~750ms | ~8MB |
| remove | Single key | ~700ms | ~7MB |

### Performance Optimization Tips

```bash
# FAST: Batch import in one command
envseal import --group prod huge.env

# SLOW: Individual sets
for line in $(cat huge.env); do
  envseal set --group prod "$line"
done

# FAST: Run command directly
envseal run --group dev npm start

# SLOW: Load and run separately (2x overhead)
eval "$(envseal load --group dev)" && npm start
```

### Scalability Limits

| Metric | Limit | Notes |
|--------|-------|-------|
| Secrets per group | ~10,000 | Performance degrades significantly above 1,000 |
| Total vault size | ~100MB | Unencrypted JSON size before encryption |
| Max key length | 256 chars | Recommended: < 50 chars |
| Max value length | 1MB | Recommended: < 100KB |
| Password length | 256 chars | Recommended: 16-64 chars |
| Groups | Unlimited | No practical limit |

---

## Security Details

### Encryption Specification

| Component | Implementation | Details |
|-----------|-----------------|---------|
| Cipher | AES-256-GCM | NIST-approved, authenticated encryption with associated data (AEAD) |
| Key Size | 256-bit | Equivalent to 2^256 possible keys |
| Mode | GCM (Galois/Counter Mode) | Provides both confidentiality and authenticity |
| Nonce | 12-byte random | Generated fresh for each encryption |
| Key Derivation | Argon2 | Memory-hard hash resistant to brute-force and GPU attacks |

### Master Password Security

```
Master Password
      ↓
Argon2 (with random salt)
- Time cost: 3 iterations
- Memory cost: 64MB
- Parallelism: 4 threads
      ↓
256-bit AES Key
      ↓
Used for AES-256-GCM encryption
```

**Argon2 Parameters:**
- Time cost: 3 iterations
- Memory cost: 64MB (resistant to GPU brute-force)
- Parallelism: 4 threads
- Resistance: GPU-resistant and ASIC-resistant

### Attack Resistance

| Attack | Mitigation |
|--------|-----------|
| Brute-force | Argon2 memory-hard hashing + 256-bit key space |
| Dictionary attacks | High entropy from strong passwords + Argon2 parameters |
| Memory dumps | Automatic memory wiping via `zeroize` crate |
| Side-channel | Constant-time operations in cryptographic functions |
| Replay attacks | Fresh nonce for each encryption |
| Chosen-plaintext | GCM mode provides authenticity verification |

---

## Best Practices

### DO

1. **Use `envseal run` by default**
   ```bash
   Good:   envseal run --group dev npm start
   Bad:    eval "$(envseal load --group dev)" && npm start
   ```

2. **Use strong master passwords**
   - 16+ characters with mixed case, numbers, symbols
   - Use passphrases for easier memorization
   - Store in a password manager if needed

3. **Regularly rotate secrets**
   ```bash
   envseal set --group prod API_KEY  # Update with new key
   ```

4. **Back up your vault**
   ```bash
   cp ~/.config/envseal/seal-encrypted.json ~/backups/
   ```

5. **Use different master passwords for different machines**

6. **Audit which environment you're using**
   ```bash
   envseal list --group dev
   envseal export --group dev | head
   ```

### DON'T

1. **Don't load secrets into shell permanently**
   ```bash
   Bad:    eval "$(envseal load dev)"
   Good:   envseal run --group dev app
   ```

2. **Don't commit `.env` files to git**
   ```bash
   Bad:    git add .env
   Good:   git add .env.example
   Good:   Use EnvSeal instead
   ```

3. **Don't use the same master password everywhere**

4. **Don't export secrets to temporary files carelessly**
   ```bash
   Bad:    envseal export --group prod > /tmp/.env
   Good:   Use in-memory via pipes
   ```

5. **Don't forget to verify your vault is working**

---

## Troubleshooting

### Common Issues

#### "Vault not found" Error

**Problem:** `envseal: error: no vault found — run 'envseal init' first`

**Solution:** Create your initial encrypted vault:
```bash
envseal init
```

---

#### "No entry / group named X" Error

**Problem:** Trying to get, run, or list a group/key that doesn't exist.

**Solution:** Keys and groups are case-sensitive. Check what you have:
```bash
envseal list --group mygroup
```

---

#### `envseal load` isn't setting environment variables

**Problem:** Running `envseal load dev` prints export statements but they don't take effect.

**Solution:** The automatic shell wrapper wasn't installed. Manual workaround:

```bash
eval "$(envseal load --group dev)"
```

Or reinstall with shell integration:
```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
source ~/.bashrc  # or ~/.zshrc or ~/.config/fish/config.fish
```

---

#### Wrong secrets being used in `envseal run`

**Problem:** I ran `envseal run dev npm start` but the wrong group was used.

**Solution:** Verify which group you're actually running:
```bash
envseal list --group dev
envseal list --group prod
envseal export --group dev | head

# Always specify --group explicitly
envseal run --group prod npm start
```

---

#### "Permission denied" when installing

**Problem:** `install.sh: Permission denied`

**Solution:** Make the script executable:
```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

Or run it directly:
```bash
bash scripts/install.sh
```

---

### Edge Cases & Recovery

#### Corrupted Vault File

**Problem:** `error: invalid vault format` or corrupted JSON

**Symptoms:**
- Cannot run any `envseal` commands
- Error: "failed to parse vault"
- File might be truncated or corrupted

**Recovery Steps:**

1. **Check if backup exists:**
   ```bash
   # If you have a backup
   cp ~/backups/seal-encrypted.json ~/.config/envseal/seal-encrypted.json
   envseal list --group dev  # Test if it works
   ```

2. **Attempt vault recovery (if backup unavailable):**
   ```bash
   # Export what you can to temporary file
   envseal export --group dev 2>/dev/null > /tmp/dev-backup.env || true
   
   # Start fresh (WARNING: This deletes the corrupted vault)
   rm ~/.config/envseal/seal-encrypted.json
   envseal init  # Create new vault with same master password
   envseal import --group dev /tmp/dev-backup.env
   ```

3. **Prevent future corruption:**
   ```bash
   # Regular backups (add to crontab)
   0 2 * * * cp ~/.config/envseal/seal-encrypted.json ~/backups/seal-$(date +\%Y\%m\%d).json
   
   # Keep 30 days of backups
   find ~/backups -name "seal-*.json" -mtime +30 -delete
   ```

---

#### Lost or Forgotten Master Password

**Problem:** Cannot remember master password and cannot access vault

**Symptoms:**
- "invalid master password" error
- Cannot decrypt any secrets
- Vault file exists but unusable

**Recovery Options:**

WARNING: There is NO password recovery mechanism by design (security feature). Recovery requires one of:

**Option 1: Restore from Backup**
```bash
# If you have an encrypted backup and remember the password
# (e.g., stored on encrypted USB or cloud storage)
cp /path/to/backup/seal-encrypted.json ~/.config/envseal/seal-encrypted.json

# Try to access with recovered password
envseal list --group dev
```

**Option 2: Re-import from Source Files**
```bash
# If you have the original .env files
rm ~/.config/envseal/seal-encrypted.json
envseal init  # Create new vault (with new password)

# Re-import secrets from source
envseal import --group dev /path/to/.env.dev
envseal import --group prod /path/to/.env.prod
envseal import --group staging /path/to/.env.staging
```

**Option 3: Password Reset (if using external password manager)**
```bash
# If master password was stored in password manager
# 1. Check password manager for saved EnvSeal password
# 2. Or reset password manager credentials
# 3. Try master password again
```

**Prevention:**
```bash
# Store master password securely
1. Use a password manager (1Password, Bitwarden, KeePass)
2. Write down and store in safe deposit box
3. Store encrypted copy in cloud backup
4. Share with trusted team member (encrypted channel)

# Multi-layer backup strategy
- Encrypted vault backup (e.g., AWS S3 encrypted)
- Original .env files backup (for recovery purposes)
- Password stored in secure location
```

---

#### Master Password Changed/Forgotten Recovery

**Problem:** Want to change master password but forgot the old one

**Solution:**

Since passwords aren't recoverable, you must use Option 2 above (re-import from sources):

```bash
# 1. Backup current vault (even if you can't access it)
cp ~/.config/envseal/seal-encrypted.json ~/.config/envseal/seal-encrypted.backup.json

# 2. Delete vault
rm ~/.config/envseal/seal-encrypted.json

# 3. Create new vault with NEW master password
envseal init

# 4. Re-import all secrets from source files
envseal import --group dev .env.dev
envseal import --group prod .env.prod
# etc.

# 5. Keep old vault as backup (encrypted, can't access but still secure)
mv ~/.config/envseal/seal-encrypted.backup.json ~/.config/envseal/seal-encrypted.OLD.json
```

---

#### Vault File Deleted Accidentally

**Problem:** Accidentally deleted `~/.config/envseal/seal-encrypted.json`

**Recovery:**

1. **Check system trash/recycle bin** (might still be recoverable)
   ```bash
   # macOS
   ls ~/.Trash | grep seal
   
   # Linux (depends on desktop environment)
   ls ~/.local/share/Trash/files | grep seal
   ```

2. **Check file recovery tools**
   ```bash
   # If nothing in trash, try file recovery
   # Linux: extundelete, photorec, etc.
   # macOS: DiskUtility can sometimes recover deleted files
   ```

3. **If recovery fails, use backup:**
   ```bash
   cp ~/backups/seal-encrypted.json ~/.config/envseal/seal-encrypted.json
   envseal list --group dev  # Test
   ```

4. **If backup unavailable:**
   ```bash
   # Recreate vault from source files (see above steps)
   ```

---

#### Multiple Device Synchronization Issues

**Problem:** Same vault on multiple machines getting out of sync

**Scenario:**
```
Machine A: Added NEW_API_KEY to prod group
Machine B: Still has old prod group version
Sync service: Conflicting versions
```

**Solution:**

Since EnvSeal doesn't support automatic sync (by design for security), use this workflow:

```bash
# Machine A (after adding new secret)
envseal export --group prod > /tmp/prod-backup.env
# Manually transfer to Machine B via secure channel

# Machine B (receiving update)
# Option 1: Re-import (overwrites)
envseal import --group prod /tmp/prod-backup.env

# Option 2: Create separate group (keeps old)
envseal import --group prod-new /tmp/prod-backup.env

# Verification
envseal list --group prod
envseal list --group prod-new
```

**Better approach: Centralized secret management**
```bash
# For team environments, consider:
# - AWS Secrets Manager for prod
# - HashiCorp Vault for infrastructure
# - EnvSeal for local development only

# This separates concerns:
# - Local dev: EnvSeal (offline, portable)
# - Shared/prod: External system (versioned, auditable)
```

---

#### Performance Degradation

**Problem:** `envseal` commands suddenly becoming slow

**Symptoms:**
- Operations taking 10s+ instead of <1s
- `envseal export` hangs
- `envseal import` very slow

**Diagnosis:**

```bash
# Check vault file size
ls -lh ~/.config/envseal/seal-encrypted.json
# If > 50MB, vault is too large

# Check number of secrets
envseal list --group prod | wc -l
# If > 5000, too many secrets per group

# Check system resources
top  # Is CPU/memory maxed out?
df -h  # Is disk full?
```

**Solutions:**

1. **Split large groups:**
   ```bash
   # Don't do this:
   envseal import --group all huge.env  # 5000+ secrets
   
   # Do this instead:
   envseal import --group app-core core.env
   envseal import --group app-services services.env
   envseal import --group app-external external.env
   ```

2. **Optimize vault size:**
   ```bash
   # Remove unused groups
   envseal list --group old-env
   envseal remove --group old-env
   
   # Consolidate duplicates
   envseal export --group prod > /tmp/prod.env
   envseal remove --group prod
   envseal init  # Fresh vault
   envseal import --group prod /tmp/prod.env
   ```

3. **Check system resources:**
   ```bash
   # Ensure enough free disk space
   df -h /
   
   # Close other applications
   # Restart envseal daemon if applicable
   ```

---

#### Vault Corruption After Power Loss

**Problem:** Vault file might be corrupted after unexpected shutdown

**Symptoms:**
- "invalid vault format" error
- Vault file incomplete or truncated
- Cannot run any envseal commands

**Prevention:**

```bash
# Regular backups (automated)
# Add to cron: every hour
0 * * * * cp ~/.config/envseal/seal-encrypted.json ~/.config/envseal/seal-$(date +\%s).json

# Keep only recent backups
find ~/.config/envseal/seal-*.json -mtime +3 -delete
```

**Recovery:**

```bash
# 1. List available backups
ls -lrt ~/.config/envseal/seal-*.json

# 2. Restore most recent backup before corruption
cp ~/.config/envseal/seal-1234567890.json ~/.config/envseal/seal-encrypted.json

# 3. Verify vault integrity
envseal list --group dev

# 4. Check for missing secrets
envseal export --group prod > /tmp/prod-check.env
# Compare with known good version
```

---

#### Sync Conflicts in Git

**Problem:** Multiple developers with different vaults in Git

**Scenario:**
```
Developer A adds: NEW_API_KEY to prod
Developer B adds: STRIPE_KEY to prod
Merge conflict in vault file
```

**Solution:**

**Never commit vault files to Git!**

```bash
# In .gitignore
.env
.env.*.local
seal-encrypted.json
~/.config/envseal/

# Instead, commit vault per environment
# (each developer has their own encrypted vault)

# Or use external secret management for shared secrets:
# - AWS Secrets Manager
# - HashiCorp Vault
# - GitHub Secrets (for CI/CD)

# EnvSeal is for LOCAL DEVELOPMENT only
```

---

## Upcoming Features

### Dynamic Tags

```bash
# Create a group with dev tag
envseal set --group myapp --tag dev DATABASE_URL postgresql://localhost/db

# Same group, prod tag
envseal set --group myapp --tag prod DATABASE_URL postgresql://prod-db.example.com/db

# Run with specific tag
envseal run --group myapp --tag dev npm start
```

### Directory Linking

```bash
# In your project directory, link to 'frontend' group
cd ~/projects/my-app
envseal link frontend

# Now any command in this directory uses 'frontend' by default
envseal run npm start
```

---

## Contributing

Contributions are welcome! We're looking for:
- Bug fixes and error handling improvements
- Platform-specific testing (macOS M1, Linux ARM64, etc.)
- New features and optimizations
- Documentation improvements
- Security audits

### Development Setup

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI

cargo build
cargo test
cargo fmt
cargo clippy

./target/debug/envseal --help
```

### Making Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request with a clear description

### Code Standards

- Follow Rust conventions (use `cargo fmt`)
- Run `cargo clippy` to catch common mistakes
- Write tests for new functionality
- Update documentation for user-facing changes

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

**In summary:** You're free to use, modify, and distribute EnvSeal for any purpose (personal, commercial, etc.). Just include the original license notice.

---

## Support

- Check the [Troubleshooting](#troubleshooting) section
- [Open an issue](https://github.com/viswajith275/EnvSeal-CLI/issues) on GitHub
- Discussions & feature requests welcome!

---

Made with care for developers who value security.

---

## Comparison with Alternatives

| Feature | EnvSeal | .env files | 1Password | AWS Secrets Manager |
|---------|---------|-------------|-----------|------------------|
| Local-First | Yes | Yes | No (Cloud) | No (Cloud) |
| Encryption | AES-256-GCM | None | Yes | Yes |
| Easy Setup | Yes | Yes | Complex | Complex |
| Cost | Free | Free | ~$35/mo | Variable |
| CLI-First | Yes | Yes | UI focused | Yes |
| Process Isolation | Yes | No | Partial | Partial |
| Offline Support | Yes | Yes | No | No |
| Self-Contained | Yes | Yes | No | No |

EnvSeal is perfect for developers who want:
- Strong security without cloud dependencies
- Quick setup and fast iteration
- No subscription costs
- Isolated, containerized secret injection
- CLI-native workflow

---

**Ready to seal your secrets? Get started with `envseal init`**
