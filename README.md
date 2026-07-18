**BETA BRANCH**

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
A lightweight, encrypted command-line vault for securely managing API keys, secrets, and sensitive environment variables on your local machine. EnvSeal organizes your secrets into **groups** (like `dev`, `staging`, and `prod`) so you can seamlessly switch environments or inject secrets directly into application processes.

**Version:** see [Releases](https://github.com/viswajith275/EnvSeal-CLI/releases) for the current version and changelog.

## Table of Contents

* [Problem and Solution](#problem-and-solution)
* [Features](#features)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Commands](#commands)
* [Security](#security)
* [Use Cases](#use-cases)
* [Troubleshooting](#troubleshooting)
* [Contributing](#contributing)
* [License](#license)


---

## Upcoming Features

* **Dynamic Tags**: Change crucial variables on the fly. Create local and prod tags to swap out specific values—like localhost vs. a production DB—while the rest of your group settings stay exactly the same.

* **Directory Linking**: Bind a specific group to your current working directory. Once linked, you can run commands in that folder without needing to repeatedly type or remember the group name. (Global access via the group name will still work from any other directory).

---

## Problem and Solution

### The Problem

Developers often struggle with securely managing API keys, tokens, and sensitive credentials:

* **Plain-text storage**: Keeping secrets in `.env` files or shell scripts exposes them to accidental commits and unauthorized access.
* **Environment sprawl**: Switching between different API keys for different environments (dev, staging, prod) is tedious and error-prone.
* **Global scope leaks**: Loading secrets into your global terminal session means any background script can access them.
* **Scattered secrets**: API keys scattered across multiple config files are hard to audit and manage.

### The Solution

**EnvSeal** provides:

✅ **Group-Based Management**: Organize secrets into environments (e.g., `dev`, `prod`) and switch seamlessly.

✅ **Secure Process Injection**: Use `envseal run` to inject secrets only into a specific child process without exposing them to your terminal session.

✅ **End-to-End Encryption**: All sensitive data is encrypted at rest using military-grade AES-256-GCM.

✅ **Master Password Protection**: The vault is locked behind a single, strong master password (derived via Argon2).

✅ **Drop-in `.env` Replacement**: Easily import existing `.env` files or export groups back out.

✅ **Memory Safety**: Built in Rust with automatic memory wiping to prevent secret leaks.

---

## Features

* **Group Organization**: Group your variables by project or environment (creates groups automatically on first set).
* **Child Process Execution**: Safely run applications with decrypted variables injected directly into their environment.
* **Bulk Import/Export**: Instantly parse `.env` files into encrypted groups, or output groups to `.env` format.
* **End-to-End Encryption**: Secrets encrypted with AES-256-GCM.
* **Memory Safe**: Automatic memory wiping prevents sensitive data leaks.
* **Cross-Platform**: Works on Linux, macOS (Intel & Apple Silicon), with support for bash, zsh, and fish.

---

## Installation

Choose your preferred installation method.

### Method 1: Automated Installation (Recommended)

Download and run the installation script. This always fetches the install script attached to the *latest* GitHub release.

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/envseal-cli/master/install.sh | bash

```

The installer will auto-detect your OS and architecture, download the matching binary, add it to your PATH, and set up automatic shell integration for `envseal load`.

### Method 2: Build from Source

Prerequisites: [Rust 1.70+](https://www.rust-lang.org/tools/install) and `cargo`.

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal
cargo build --release

# Move to your PATH
mv target/release/envseal ~/.local/bin/envseal
chmod +x ~/.local/bin/envseal

```

---

## Quick Start

### 1. Initialize Your Vault

Run the initialization command and set a strong master password:

```bash
envseal init

```

### 2. Store Secrets in a Group

Store your development secrets in a group named `dev` (the group is created automatically):

```bash
envseal set dev DATABASE_URL
# Prompts for master password and the secret value

```

### 3. Import an Existing `.env` File

Migrate a plain-text `.env` file into an encrypted group named `prod`:

```bash
envseal import prod .env.production

```

### 4. Run an Application Safely

Inject your group's secrets directly into a process without leaking them to the terminal:

```bash
envseal run dev npm start

```

*(This is the recommended workflow. It prompts for your master password once, decrypts the variables, and executes `npm start` with those variables injected.)*

---

## Commands

### `envseal init`

Initialize a new encrypted vault with a master password.

* Creates an encrypted vault file in your OS config directory (`~/.config/dev.envseal.envseal/seal-encrypted.json`).
* Prompts for master password setup and confirmation.

### `envseal set <GROUP_NAME> <KEY>`

Set or update a value for a given key in a group. If the group doesn't exist, it is created.

```bash
envseal set dev GITHUB_TOKEN

```

### `envseal get <GROUP_NAME> <KEY>`

Retrieve a stored secret from a specific group.

```bash
envseal get dev GITHUB_TOKEN

```

### `envseal import <GROUP_NAME> <PATH_OF_.ENV>`

Reads a `.env` file and securely loads all key-value pairs into the specified vault group.

```bash
envseal import staging /path/to/staging.env

```

### `envseal export <GROUP_NAME> > .env`

Decrypts and outputs the entire group in standard `.env` format. You can pipe this directly into a file.

```bash
envseal export prod > .env.production

```

### `envseal run <GROUP_NAME> <COMMAND>`

**(Recommended)** Loads the environment variables for the group into a child process and executes the command. The variables are *not* exposed to your parent terminal session.

```bash
envseal run dev python app.py

```

### `envseal load <GROUP_NAME> [KEYS...]`

Loads the specified keys (or the entire group if keys are omitted) into the current terminal environment.
*Note: For security and scoping, use `run` for most use cases.*

```bash
# Loads the entire group into current shell (if shell integration is installed)
envseal load dev

# Loads specific keys
envseal load dev DATABASE_URL API_KEY

```

### `envseal list <GROUP_NAME>`

List all keys currently stored inside a specific group.

```bash
envseal list dev

```

### `envseal remove <GROUP_NAME> [KEY]`

Deletes a specific key from a group. If no key is provided, the **entire group** is deleted.

```bash
# Remove a single key
envseal remove dev OLD_API_KEY

# Delete the entire dev group
envseal remove dev

```

---

## Security

### Encryption Details

* **Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data)
* **Key Derivation**: Argon2 (memory-hard password hashing)
* **Random Nonce**: 12-byte randomly generated nonce per encryption
* **Memory Safety**: Uses the `zeroize` crate to wipe sensitive data from memory immediately after use.

### Best Practices

* **Prefer `envseal run**`: Injecting secrets directly into child processes using `run` is significantly safer than using `load`, which leaves credentials hanging in your active terminal session.
* **Protect the Vault**: While the vault is encrypted, ensure your machine utilizes full-disk encryption and proper file permissions.

---

## Use Cases

### Local Development Across Environments

Instead of swapping `.env` files manually, store them in groups and run your app contextually:

```bash
# Initial setup
envseal import dev .env.dev
envseal import staging .env.staging
envseal import prod .env.prod

# Work on local dev
envseal run dev npm start

# Test against staging database
envseal run staging npm start

```

### CI/CD Pipeline Local Testing

Test your deployment scripts locally without hardcoding secrets:

```bash
envseal run deploy ./scripts/deploy_to_aws.sh

```

---

## Troubleshooting

### "Vault not found" Error

**Problem**: `envseal: error: no vault found — run 'envseal init' first`
**Solution**: Run `envseal init` to create your initial encrypted vault.

### "No entry / group named X" Error

**Problem**: Trying to get, run, or list a group/key that doesn't exist.
**Solution**: Keys and groups are case-sensitive. Use `envseal list <GROUP_NAME>` to check the exact spelling.

### `envseal load` isn't setting environment variables

**Problem**: Running `envseal load GROUP` prints export statements but they don't seem to take effect.
**Solution**: This happens if the automatic shell wrapper wasn't installed. As an immediate workaround, evaluate the output manually:

```bash
eval "$(envseal load dev)"

```

Alternatively, switch to using `envseal run dev <command>`.

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal
cargo build
cargo test
cargo fmt
cargo clippy

```

---

## License

This project is licensed under the MIT License — see the LICENSE file for details.
