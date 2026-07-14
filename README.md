# envfuse-CLI

A lightweight, encrypted command-line vault for securely managing API keys, secrets, and sensitive environment variables on your local machine.

**Version:** see [Releases](https://github.com/viswajith275/envfuse-CLI/releases) for the current version and changelog.

## Table of Contents

- [Problem & Solution](#problem--solution)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## Problem & Solution

### The Problem

Developers often struggle with securely managing API keys, tokens, and sensitive credentials:

- **Plain-text storage**: Keeping secrets in `.env` files or shell scripts exposes them to accidental commits and unauthorized access
- **Manual management**: Switching between different API keys for different environments is tedious and error-prone
- **No encryption**: Standard environment variable management lacks built-in encryption
- **Security breaches**: A single compromised machine can expose all stored credentials if they're not encrypted
- **Scattered secrets**: API keys scattered across multiple config files are hard to audit and manage

### The Solution

**envfuse-CLI** provides:

✅ **AES-256-GCM Encryption**: All sensitive data is encrypted at rest using military-grade encryption
✅ **Master Password Protection**: Vault locked behind a single, strong master password
✅ **Easy Secret Management**: Simple commands to set, get, and manage secrets
✅ **Automatic Shell Integration**: The installer wires up a shell function so `envfuse load` "just works" — no manual `eval` needed
✅ **Cross-Platform**: Works on Linux (x86_64), macOS (Intel & Apple Silicon), with bash, zsh, and fish support
✅ **Password Derivation**: Uses Argon2 for secure password hashing
✅ **Memory Safety**: Built in Rust with automatic memory wiping to prevent secret leaks

---

## Features

-  **End-to-End Encryption**: Secrets encrypted with AES-256-GCM
-  **Master Password Protection**: Single master password protects all secrets
-  **Lightweight Binary**: Single compiled executable, no dependencies required
-  **Fast**: Written in Rust for blazing-fast performance
-  **Memory Safe**: Automatic memory wiping prevents sensitive data leaks
-  **Zero-Friction Shell Integration**: Load secrets directly into your bash/zsh/fish environment with a single command — no `eval` boilerplate required
-  **Simple CLI**: Intuitive commands for managing secrets
-  **OS-Aware Storage**: Vault stored in standard config directory for your OS

---

## Installation

Choose your preferred installation method. All methods below always install the **latest** release unless you pass a specific version — so these commands never need to be edited when a new version ships.

### Method 1: Automated Installation (Recommended)

Download and run the installation script. This always fetches the install script attached to the *latest* GitHub release, so the command below stays correct forever — you never need to update a version number in it:

```bash
curl -sSL https://github.com/viswajith275/envfuse-CLI/releases/latest/download/install.sh | bash
```

The installer will:
- Auto-detect your OS and architecture
- Download the matching pre-compiled binary (latest release, by default)
- Add the binary to your PATH
- Set up automatic shell integration for **bash**, **zsh**, and **fish**

You can customize the install with flags, passed after `-s --`:

```bash
# Install to a custom directory
curl -sSL https://github.com/viswajith275/envfuse-CLI/releases/latest/download/install.sh | bash -s -- --dir /usr/local/bin

# Pin to a specific version instead of latest
curl -sSL https://github.com/viswajith275/envfuse-CLI/releases/latest/download/install.sh | bash -s -- --version v1.0.1
```

> Note: `--version` controls which release of the **binary** is downloaded. The install script itself is always pulled from `releases/latest`, since the script's own logic rarely changes between versions.

### Method 2: Manual Installation via Release Artifacts

1. **Download the binary** for your platform from the [latest release](https://github.com/viswajith275/envfuse-CLI/releases/latest):
   - `envfuse-macos-x86_64.tar.gz` (macOS Intel)
   - `envfuse-macos-aarch64.tar.gz` (macOS Apple Silicon M1/M2/M3)
   - `envfuse-linux-musl-x86_64.tar.gz` (Linux x86_64)

2. **Extract and install**:
   ```bash
   # Extract the archive
   tar -xzf envfuse-*.tar.gz

   # Move to your PATH
   mv envfuse-* ~/.local/bin/envfuse
   chmod +x ~/.local/bin/envfuse

   # Ensure ~/.local/bin is in your PATH
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. **Add to your shell config** (`.bashrc`, `.zshrc`, or `~/.config/fish/config.fish`):
   ```bash
   export PATH="$HOME/.local/bin:$PATH"          # bash / zsh
   # fish_add_path $HOME/.local/bin               # fish
   ```

   With a manual install you'll also miss the automatic `envfuse load` shell wrapper (see [Load Secrets into Your Shell](#4-load-secrets-into-your-shell)). If you want that convenience, use Method 1 or Method 4 instead, or use `eval "$(envfuse load ...)"` directly.

4. **Reload your shell**:
   ```bash
   source ~/.bashrc                              # bash
   source ~/.zshrc                                # zsh
   source ~/.config/fish/config.fish              # fish
   ```

### Method 3: Build from Source

Prerequisites:
- [Rust 1.70+](https://www.rust-lang.org/tools/install)
- `cargo`

```bash
# Clone the repository
git clone https://github.com/viswajith275/envfuse-CLI.git
cd envfuse-CLI

# Build the release binary
cargo build --release

# Verify installation
./target/release/envfuse --version
```

To get the automatic shell integration (PATH + the `envfuse load` wrapper function) after building from source, run the install script against your local binary — see Method 4 below.

### Method 4: Using the Installation Script with a Local Binary

If you've built the binary locally or already have a pre-built binary or tarball downloaded, point the installer at it directly. This skips the network download entirely but still sets up your PATH and shell integration:

```bash
# From a locally-built binary
./install.sh --file ./target/release/envfuse

# From a downloaded tarball
./install.sh --file ~/Downloads/envfuse-macos-aarch64.tar.gz
```

### Verify Installation

```bash
envfuse --help
```

You should see the available commands and options.

---

## Quick Start

### 1. Initialize Your Vault

Run the initialization command and set a strong master password:

```bash
envfuse init
```

Output:
```
                                /$$$$$$
                               /$$__  $$
  /$$$$$$  /$$$$$$$  /$$    /$$| $$  \__//$$   /$$  /$$$$$$$  /$$$$$$
 /$$__  $$| $$__  $$|  $$  /$$/| $$$$   | $$  | $$ /$$_____/ /$$__  $$
| $$$$$$$$| $$  \ $$ \  $$/$$/ | $$_/   | $$  | $$|  $$$$$$ | $$$$$$$$
| $$_____/| $$  | $$  \  $$$/  | $$     | $$  | $$ \____  $$| $$_____/
|  $$$$$$$| $$  | $$   \  $/   | $$     |  $$$$$$/ /$$$$$$$/|  $$$$$$$
 \_______/|__/  |__/    \_/    |__/      \______/ |_______/  \_______/

Set a master password: ••••••••••
Confirm master password: ••••••••••
Vault created at /Users/username/.config/envfuse/vault-encrypted.json
```

### 2. Store a Secret

```bash
envfuse set GITHUB_TOKEN
# Enter your GitHub token when prompted
```

### 3. Retrieve a Secret

```bash
envfuse get GITHUB_TOKEN
# Outputs your GitHub token (requires master password)
```

### 4. Load Secrets into Your Shell

If you installed via Method 1 or Method 4, the installer already added an `envfuse()` shell function to your `.bashrc` / `.zshrc` / `fish` config. That function automatically detects the `load` subcommand and applies its output to your current shell — **no `eval` needed**:

```bash
envfuse load GITHUB_TOKEN DATABASE_URL API_KEY
```

This prompts for your master password once and exports all specified secrets as environment variables directly into your current shell session.

If you installed manually (Method 2 or Method 3) and skipped shell integration, or you're calling the real binary explicitly (e.g. `command envfuse`), fall back to the manual form:

```bash
eval "$(envfuse load GITHUB_TOKEN DATABASE_URL API_KEY)"
```

**Usage in scripts** (always use the explicit `eval` form here, since scripts may not source your interactive shell config):

```bash
#!/bin/bash
eval "$(envfuse load DATABASE_URL API_KEY)"
echo $DATABASE_URL  # Access loaded secrets
```

### 5. List All Stored Secrets

```bash
envfuse list
# Shows all secret names (not their values)
```

### 6. Remove a Secret

```bash
envfuse remove GITHUB_TOKEN
# Removes the secret from the vault
```

---

## Commands

### `envfuse init`

Initialize a new encrypted vault with a master password.

```bash
envfuse init
```

- Creates an encrypted vault file in your OS config directory
- Prompts for master password setup and confirmation
- Validates password strength (recommend 12+ characters)

**Storage location:**
- Linux: `~/.config/envfuse/vault-encrypted.json`
- macOS: `~/Library/Application Support/envfuse/vault-encrypted.json`

---

### `envfuse set <KEY>`

Store a new secret or update an existing one.

```bash
envfuse set GITHUB_TOKEN
# Or with a value directly:
envfuse set DATABASE_URL "postgresql://user:pass@localhost/db"
```

- Prompts for master password
- Encrypts and stores the secret
- Automatically creates/updates the vault

---

### `envfuse get <KEY>`

Retrieve a stored secret.

```bash
envfuse get GITHUB_TOKEN
```

- Prompts for master password
- Decrypts and displays the secret
- Returns error if the key doesn't exist

---

### `envfuse load <KEYS...>`

Load multiple secrets into your shell environment.

```bash
envfuse load GITHUB_TOKEN DATABASE_URL API_KEY
```

- Prompts for master password (once)
- Outputs shell export commands
- If you used the automated installer, calling `envfuse load ...` directly in an interactive bash/zsh/fish session already applies the exports — the wrapper function runs `eval` for you.
- Otherwise, wrap it with `eval` yourself:

```bash
eval "$(envfuse load GITHUB_TOKEN DATABASE_URL)"
```

**Usage in scripts:**

```bash
#!/bin/bash
eval "$(envfuse load DATABASE_URL API_KEY)"
echo $DATABASE_URL  # Access loaded secrets
```

---

### `envfuse list`

List all stored secret names.

```bash
envfuse list
```

- Prompts for master password
- Shows all keys in your vault
- Does not display secret values

---

### `envfuse remove <KEY>`

Delete a secret from the vault.

```bash
envfuse remove GITHUB_TOKEN
```

- Prompts for master password
- Removes the specified key
- Returns error if the key doesn't exist

---

## Security

### Encryption Details

envfuse-CLI uses industry-standard encryption:

- **Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **Key Derivation**: Argon2 (memory-hard password hashing)
- **Random Nonce**: 12-byte randomly generated nonce per encryption
- **Salt**: 16-byte random salt for key derivation
- **Authenticated Tags**: Each encrypted value includes authentication tags to prevent tampering

### Security Best Practices

1. **Use a Strong Master Password**
   - At least 12 characters
   - Mix of uppercase, lowercase, numbers, and symbols
   - Avoid dictionary words and personal information

2. **Protect Your Vault File**
   - The vault file is encrypted but should still be protected
   - Use full-disk encryption on your machine
   - Don't back up the vault file to unsecured locations
   - Keep your machine secure and up-to-date

3. **Be Careful When Loading Secrets**
   - Only load secrets you need for a specific task
   - Avoid loading secrets into long-running shell sessions unnecessarily
   - The automatic `envfuse load` shell integration only runs `eval` on output from the real `envfuse` binary invoked via `command`, so it can't recurse into itself — but you should still only install envfuse-CLI from sources you trust

4. **Master Password**
   - Never share your master password
   - Consider using a password manager to store it securely
   - Change it periodically for added security

### Memory Safety

- Written in Rust with memory safety guarantees
- Sensitive data is automatically wiped from memory after use via the `zeroize` crate
- No garbage collection delays that could expose secrets
- Stack-based encryption operations reduce timing attack surface

### Vault File Format

The vault file (`vault-encrypted.json`) contains:
- **salt**: Randomly generated salt (Base64-encoded)
- **canary**: Encrypted test data to verify password correctness
- **entries**: Your encrypted secrets (Base64-encoded nonce + ciphertext pairs)

The file itself is not encrypted at the file-system level; rely on:
- Full-disk encryption
- File permissions (`chmod 600`)
- Your operating system's access controls

---

## Use Cases

### Development Workflow

Store API keys used in development:

```bash
# Initialize once
envfuse init

# Store your development secrets
envfuse set GITHUB_TOKEN
envfuse set OPENAI_API_KEY
envfuse set DATABASE_URL

# Load them when needed (no eval needed with the automated installer)
envfuse load GITHUB_TOKEN OPENAI_API_KEY DATABASE_URL

# Use in your application
npm start  # Your app can now access these env vars
```

### CI/CD Secrets (Local Testing)

Test CI scripts locally with real secrets. In non-interactive scripts, always use the explicit `eval` form since the shell wrapper only applies to interactive sessions sourced from your rc file:

```bash
eval "$(envfuse load DEPLOY_KEY AWS_ACCESS_KEY)"
./deploy.sh
```

### Multiple Environment Management

Store secrets for different environments:

```bash
# Development
envfuse set DEV_DATABASE_URL
envfuse set DEV_API_KEY

# Staging
envfuse set STAGING_DATABASE_URL
envfuse set STAGING_API_KEY

# Production
envfuse set PROD_DATABASE_URL
envfuse set PROD_API_KEY

# Load environment-specific secrets
envfuse load DEV_DATABASE_URL DEV_API_KEY
```

---

## Troubleshooting

### "Vault not found" Error

**Problem**: `envfuse: error: no vault found — run 'envfuse init' first`

**Solution**: Initialize your vault:
```bash
envfuse init
```

### "Wrong Master Password" Error

**Problem**: `envfuse: error: wrong master password`

**Solution**:
- Ensure you're entering the correct master password
- Check for CAPS LOCK or other input issues
- If forgotten, you'll need to reinitialize (data cannot be recovered)

### "No entry named X" Error

**Problem**: `envfuse: error: no entry named 'SOME_KEY'`

**Solution**:
- Check the exact spelling: `envfuse list` shows all available keys
- Keys are case-sensitive
- Make sure you've stored the key first: `envfuse set SOME_KEY`

### Installation Path Issues

**Problem**: `envfuse: command not found` after installation

**Solution**:
- Verify installation: `which envfuse` or `echo $PATH`
- Add to PATH manually if needed:
  ```bash
  export PATH="$HOME/.local/bin:$PATH"          # bash / zsh
  fish_add_path $HOME/.local/bin                 # fish
  ```
- Reload your shell:
  ```bash
  source ~/.bashrc                               # bash
  source ~/.zshrc                                 # zsh
  source ~/.config/fish/config.fish                # fish
  ```

### `envfuse load` isn't setting environment variables in my shell

**Problem**: Running `envfuse load KEY` prints export statements but they don't seem to take effect.

**Solution**: This means the automatic shell wrapper wasn't installed or wasn't loaded into your current session:
- Confirm the wrapper exists: `type envfuse` should show a shell function, not just a binary path
- If it only shows the binary path, re-run the installer (Method 1 or Method 4) or restart your shell/terminal
- As an immediate workaround, use the explicit form: `eval "$(envfuse load KEY)"`

### Permission Denied

**Problem**: `Permission denied` when running envfuse

**Solution**:
```bash
chmod +x /path/to/envfuse
# Then run it again
```

---

## Project Structure

```
envfuse-CLI/
├── src/
│   ├── main.rs              # Entry point
│   ├── cli.rs               # Command-line interface definitions
│   ├── commands/            # Command implementations
│   │   ├── init.rs          # Vault initialization
│   │   ├── set.rs           # Store secrets
│   │   ├── get.rs           # Retrieve secrets
│   │   ├── load.rs          # Load multiple secrets to shell
│   │   ├── list.rs          # List secret names
│   │   ├── remove.rs        # Delete secrets
│   │   └── mod.rs           # Module definitions
│   └── utils/               # Utility modules
│       ├── crypto.rs        # Encryption/decryption logic
│       ├── vault.rs         # Vault management
│       └── mod.rs           # Module definitions
├── Cargo.toml               # Rust dependencies
├── install.sh               # Installation script
└── README.md                # This file
```

---

## Dependencies

envfuse-CLI uses well-maintained, audited Rust crates:

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4.x | Command-line argument parsing |
| `aes-gcm` | 0.11 | AES-256-GCM encryption |
| `argon2` | 0.5 | Password derivation |
| `serde` | 1.x | JSON serialization |
| `serde_json` | 1.x | JSON handling |
| `rand` | 0.8 | Random number generation |
| `zeroize` | 1.x | Secure memory wiping |
| `base64` | 0.22 | Base64 encoding |
| `rpassword` | 7.x | Secure password input |
| `directories` | 6.0 | OS config directory detection |
| `anyhow` | 1.x | Error handling |

---

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux | x86_64 | ✅ Supported |
| macOS | x86_64 (Intel) | ✅ Supported |
| macOS | aarch64 (Apple Silicon) | ✅ Supported |
| Windows | - | ⏳ Planned |

Shell integration is supported for **bash**, **zsh**, and **fish**.

---

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add tests
4. Commit: `git commit -am 'Add your feature'`
5. Push: `git push origin feature/your-feature`
6. Open a Pull Request

### Development Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/envfuse-CLI.git
cd envfuse-CLI

# Build
cargo build

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

---

## License

This project is licensed under the MIT License — see the LICENSE file for details.

---

## Support & Feedback

- 🐛 **Found a bug?** Open an [issue](https://github.com/viswajith275/envfuse-CLI/issues)
- 💡 **Have a suggestion?** Start a [discussion](https://github.com/viswajith275/envfuse-CLI/discussions)
- ⭐ **Like the project?** Star this repository!

---

## Changelog

Full changelog is maintained on the [GitHub Releases page](https://github.com/viswajith275/envfuse-CLI/releases) so it never drifts out of sync with this README.

---

**Made with ❤️ by [viswajith275](https://github.com/viswajith275)**
