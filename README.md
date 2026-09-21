# EnvSeal CLI

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

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build](https://github.com/viswajith275/EnvSeal-CLI/actions/workflows/release.yml/badge.svg)](https://github.com/viswajith275/EnvSeal-CLI/actions)
[![Downloads](https://img.shields.io/github/downloads/viswajith275/EnvSeal-CLI/total.svg)](https://github.com/viswajith275/EnvSeal-CLI/releases)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

> **Git for secrets.** An offline, Git-native secrets manager built on SSH and Age. Your vault is a file in your repo — encrypted for the people who need it, switched by branch, and mergeable like code.

EnvSeal isn't a secrets manager. It isn't an encrypted `.env` file. It's a file in your repository that travels with `git pull`, switches with `git checkout`, resolves with `git merge`, and is reviewed in pull requests like everything else you commit.

No cloud. No accounts. No shared master password. Just Git, public keys, and a CLI that stays out of your way.

---

## Install

```bash
# Linux & macOS
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash

# Windows
winget install --id viswajith275.envseal -e

# From source
cargo install envseal
```

Verify:

```bash
envseal --version
```

If the binary isn't found, make sure `~/.local/bin` or `/usr/local/bin` is on your `PATH`. On most systems the install script handles this automatically.

---

## Quick Start

```bash
# 1. Initialize the vault inside your repo
envseal init --local
envseal git-setup

# 2. Store a secret (prompts without echoing)
envseal set DATABASE_URL

# 3. Run your app with secrets injected
envseal run -- npm start

# 4. Commit the vault like any other file
git add .envseal && git commit -m "seal secrets" && git push
```

That's the entire setup. Your teammate pulls, runs `envseal run -- npm start`, and it works — same keys, correct branch, zero DMs.

**Already have a `.env`?** Import it in one step:

```bash
envseal import .env
# the original plaintext file is left for you to delete
```

**Add a teammate — two paths, depending on their setup:**

```bash
# Path A — they have SSH keys on GitHub:
# EnvSeal fetches their public SSH keys automatically.
envseal recipient add @their-github-handle

# Path B — they don't have SSH keys set up:
# They run `envseal recipient id`, which generates an age key.
# They send you the output. You add it manually.
envseal recipient add "age1ql3z7hjy54pw3hy... # priya"
```

Both work. Path A is one command with zero manual key exchange. Path B is still a single command — you just paste a key instead of a handle.

---

## Real examples

**Switching branches:**
```
$ git checkout staging
$ envseal run -- npm start
▸ loading tag 'staging' (matched current branch)
▸ DATABASE_URL → staging-db.internal
▸ STRIPE_PUBLIC_KEY → pk_test_…
```

**Accidentally staging a `.env`:**
```
$ git add .
$ git commit -m "wip"
[envseal] COMMIT REJECTED: staged plaintext .env file detected
  → .env

Unstage them, or run `envseal init --local`
to create an encrypted .envseal vault.
```

**Someone leaves the team:**
```
$ envseal recipient rm @teammate
✔ access revoked for @teammate
✔ vault re-encrypted for 3 remaining recipients
⚠ rotate the actual credentials — revocation is not a memory wipe
```

**App exits:**
```
$ envseal run -- npm start
> app@1.0.0 start
> node server.js
listening on :3000
^C
Process exited. Secrets gone. 0 plaintext bytes on disk.
```

---

## Why not SOPS? Why not dotenvx? Why not Doppler?

**SOPS** encrypts files. It's a great tool for a different job: encrypting config at rest. What it doesn't do is manage recipients, track which branch you're on, or provide a merge driver. Every new teammate means a manual age key exchange and a `sops updatekeys` run.

**dotenvx** encrypts your `.env` file and lets you commit it safely. It's a solid tool with real encryption, rotation, and git-diff audit. The difference is architectural: dotenvx uses a **single shared private key per environment**, so "who has access" is the same question as "who has the key." EnvSeal seals the vault to **individual recipients**, so adding or removing a teammate is a Git commit, not a key redistribution.

**Doppler / Infisical** are excellent products. They're also cloud services with dashboards, audit logs, and per-seat pricing. If your team needs those things, use them. Infisical can be self-hosted air-gapped, but only at the Enterprise tier.

EnvSeal is for the team in between: small, already on Git, and tired of being the unofficial IT department.

---

## The problem, if you've ever worked on a team project

If you've built anything with more than one contributor, one of these has happened to you:

- **"Wait, it works on my machine."**
  Someone adds a new API key to their local `.env`, gets the feature working, and pushes the code. Nobody else has that key. The app breaks for everyone else, and you spend the next hour in a group chat asking "does anyone know what `PAYMENT_API_KEY` is supposed to be?"

- **The `.env` file that never gets shared.**
  `.env` is gitignored for good reason, but that also means it never reaches your teammates automatically. So it gets passed around as a WhatsApp message, a Discord DM, or a copy-pasted block in a shared Google Doc — sitting there in plaintext, forever, in someone's chat history.

- **Wrong branch, wrong database.**
  You switch from `main` to a `staging` or `experiment` branch to test something, but your `.env` doesn't know that. You're now running experimental code against production data, or worse, testing against a database that doesn't have the tables your new branch expects.

- **The 2 AM `git add .`.**
  It's late, the deadline is tomorrow, and `git add .` scoops up a `.env` file along with everything else. Now there's a real API key sitting in your Git history — and if the repo is public, bots are already scanning for it.

None of these are exotic. They're what happens when secrets live outside version control and the code that needs them doesn't. The fix isn't a better `.env` file. It's putting the vault somewhere Git already knows how to move.

---

## How EnvSeal fixes this

EnvSeal keeps secrets *inside* your repository, but encrypted — so Git can do what Git is good at (syncing state across a team) without ever exposing plaintext.

- **One teammate adds a key, everyone gets it.** Push your changes, and the encrypted vault updates for the whole team. No more "can someone send me the `.env`" messages.
- **Secrets follow your branch automatically.** Check out `staging`, and EnvSeal loads the `staging`-tagged secrets. Check out `main`, and it switches back.
- **Nothing plaintext ever touches disk or chat.** Secrets decrypt directly into the memory of the process you're running, and disappear when it exits.
- **A pre-commit hook stops the panic push.** If you (or a sleepy teammate) accidentally try to commit a raw `.env` file, EnvSeal blocks it before it reaches Git history.
- **Migration is one command.** Already have a `.env`? `envseal import .env` brings it into the vault. Need a temporary plaintext file for a legacy tool? `envseal export` writes it with strict `0600` permissions.
- **Interactive shell when you want it.** `envseal load` prints export statements so you can `eval "$(envseal load)"` — useful for debugging, while `envseal run` remains the safe default for everyday work.

In short: EnvSeal is what happens when you get tired of being the unofficial IT department for your own group project.

**Bonus:** Because the vault is just a file in the repo, your secrets inherit all the normal Git workflows you already use — pull requests, code review, `git blame`, and history. You can see *when* a secret was added or changed without ever seeing the value itself.

---

## Core features

### Git-native branch binding

`envseal run` checks `git rev-parse --abbrev-ref HEAD` behind the scenes. If a stored tag matches your current branch name, it's applied automatically:

```bash
git checkout feature/stripe-v2
envseal set --tag feature/stripe-v2 STRIPE_SECRET
envseal run -- cargo test   # this branch's secret + falls back to base
```

### Frictionless onboarding

New contributor joins the project? They run:

```bash
envseal recipient id
```

...send you the output, you run `envseal recipient add`, and they're in. No re-typing shared passwords into a dozen laptops.

If their GitHub account has SSH keys, you can skip the key exchange entirely:

```bash
envseal recipient add @their-github-handle
```

### Scoped tokens for CI/CD

Never paste your personal SSH or Age key into a CI runner. Mint a short-lived, narrowly scoped token instead:

```bash
envseal token --tag prod -o ./ci.token --exp 3600 STRIPE_SECRET DATABASE_URL
envseal run --token ./ci.token -- npm run migrate
```

### Instant revocation

Group member leaves the project, or a laptop gets compromised? Rotate the encryption key and every previously issued token becomes unreadable ciphertext instantly:

```bash
envseal rotate
```

### Pre-commit shield

`envseal git-setup` installs a hook that blocks staged `.env`, `.env.local`, and `.env.staging` files from ever being committed, while letting the encrypted `.envseal` file through.

### Multiple local profiles

Need separate vaults for different environments without relying only on branch tags? Use `-e` / `--env`:

```bash
envseal -e staging set DATABASE_URL
envseal -e prod run -- npm start
# targets .staging.envseal / .prod.envseal
```

### Also included

- **In-memory only decryption** — plaintext secrets exist only inside the child process you launch with `envseal run`. When that process exits, the secrets are gone.
- **Shell loading** — `envseal load` prints export statements so you can `eval "$(envseal load)"` when you intentionally want secrets in your interactive shell.
- **Easy migration** — `envseal import` brings an existing `.env` into the vault; `envseal export` writes selected keys back out with strict `0600` permissions.
- **Zero cloud dependency** — works on a plane, behind a corporate firewall, or on a completely air-gapped machine.
- **Cross-platform** — same binary behavior on Linux, macOS, and Windows.
- **Merge-driver aware** — concurrent edits to different secrets usually resolve automatically; conflicting edits on the *same* key surface a clean choice instead of a binary conflict.

---

## Global vaults: for personal scripts and one-off secrets

Not every secret belongs to a project. If you've got a handful of personal utility tokens — an AWS key for a deploy script, a personal API token for a CLI tool you wrote for yourself — you don't want a separate `.envseal` file scattered in every folder that happens to need them.

That's what the **global vault** is for: one system-wide vault, independent of any Git repo, that you can attach to as many local directories as you like.

```bash
# 1. Initialize the global vault once per machine
envseal --global init

# 2. Bind a "group" of secrets inside the global vault to the current directory
envseal link myapp

# 3. Store secrets into that group
envseal --global set AWS_ACCESS_KEY

# 4. Run your script — global secrets injected automatically
envseal --global run -- ./deploy.sh
```

Once a directory is linked to a group with `envseal link`, plain `envseal` commands run from inside that directory resolve against the linked global group automatically.

**When to reach for a global vault instead of a local one:**

- Personal deploy or maintenance scripts that aren't checked into any repo.
- One-off CLI tools you wrote for yourself that need an API key.
- Credentials you use across *many* small projects (e.g. a personal cloud provider key) where a per-repo vault would just mean copying the same secret into ten different `.envseal` files.

Local, project-scoped vaults (`envseal init --local`) are still the right call for anything a team shares — that's what travels with the repo in Git. The global vault is for secrets that belong to *you*, not to a codebase.

---

## When NOT to use EnvSeal

EnvSeal is not the right tool for every team. Skip it if:

- **You need a web dashboard, SSO, or SCIM.** EnvSeal has none of these and never will. Use Doppler or Infisical.
- **You're a solo developer with one repo.** A `.env` in `.gitignore` is fine. You don't have the problem EnvSeal solves.
- **You need compliance-grade access logs.** EnvSeal has no audit trail beyond what Git history gives you.
- **You're deep in Kubernetes or cloud-KMS.** SOPS fits your existing pipeline better.
- **Your team includes people who won't touch a terminal.** This is a CLI tool. There is no GUI. That's the design.

If none of those apply, keep reading.

---

## The deal

Most encryption tools hide their limits in the fine print. We put them on the README. Read them. If any of them is a dealbreaker, EnvSeal is not for you — and that's fine.

- **Removing someone doesn't erase what they already saw.**
  `envseal recipient rm <name>` stops a person from decrypting *future* commits, but Git history is permanent — anyone who cloned the repo earlier still has old encrypted commits and could decrypt them with a key they already hold. If someone leaves the team under bad terms, rotate the actual credentials (database password, API keys) too, not just the vault. Removing their access is not a memory wipe; it's taking away their house key after they've already made a copy.

- **`envseal rotate` protects the future, not the past.**
  Rotating generates a fresh encryption key and re-encrypts the *current* state of the vault. But it doesn't retroactively re-encrypt old Git commits. Those historical `.envseal` snapshots stay in your Git history, encrypted under the *old* key. If a leaked token ever let someone extract the underlying derived key material, they could, in theory, still use it to decrypt those old commits. The only thing that actually neutralizes a leaked secret is changing the secret itself. **If a token or key leaks, rotate the vault *and* go rotate the actual API keys or database passwords at the source.** `envseal rotate` is a good first move, not an undo button.

- **Token expiry is enforced by the CLI, not by cryptography.**
  The `--exp` flag is checked at runtime by EnvSeal itself. Because everything is offline, there's no server refusing an expired token — a sufficiently determined attacker with the raw token payload could bypass the clock check. If a CI runner is ever compromised, don't wait for the token to expire: rotate the vault and the underlying secrets immediately.

- **If you're a solo developer and you're your only recipient, you are also your own single point of failure.**
  EnvSeal has no "forgot password" button, and it never will — that's the entire point of zero-trust design. If you initialize a vault with only your own SSH or Age key as a recipient, and then your laptop dies, gets stolen, or falls in a lake, there is no cloud backup, no support ticket, and no admin override that will get your secrets back. You didn't lose your keys — they just achieved main-character energy and left without you.

  For solo projects, treat your Age/SSH identity the way you'd treat a seed phrase:
  - Back up `~/.ssh/id_ed25519` (or your Age identity file) somewhere safe and *not* inside the same repo.
  - Consider adding a second recipient anyway — a spare key of your own stored on another device, or a trusted friend — purely as a recovery path.
  - Skip both of those, and your `.envseal` file is technically "tamper-evident and encrypted forever," which is a fancy way of describing a locked box with no key, sitting quietly in your Git history for eternity.

**Extra practical advice:**

- Prefer short-lived tokens (`--exp 3600` or less) for CI.
- After any security incident, rotate *both* the vault *and* the real secrets the vault was protecting.
- Never commit the raw token files or private keys — the pre-commit shield helps, but your own habits matter more.

---

## How it compares

Pricing and capabilities verified as of early 2026.

|                              | Plain `.env`                    | dotenvx                                                  | Mozilla SOPS                                                | **EnvSeal**                                             | Doppler / Infisical                                          |
| ---------------------------- | ------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------ |
| Cost                         | Free                            | Free; paid tiers from ~$3/mo to $299/mo                  | Free                                                        | Free, no account needed                                 | Free tier; paid from ~$8–46/seat/mo depending on tier        |
| Works offline                | Yes                             | Yes — local CLI                                          | Yes with age. Cloud KMS modes need connectivity to encrypt/decrypt | Yes, fully                                       | Cached fallback only after first fetch. Infisical self-hosted available at Enterprise tier |
| Auto-switches per Git branch | No                              | No — manual `-f .env.production` selection               | No                                                          | Yes                                                     | No — requires dashboard/API config                           |
| Stops accidental commits     | No                              | Partial (`dotenvx precommit`)                            | No                                                          | Yes, built-in hook                                      | Yes, via CLI wrapper                                         |
| Team onboarding              | Manual file sharing             | Manual `.env.keys` sharing; docs recommend using 1Password | New member generates age key → added to `.sops.yaml` → `sops updatekeys` | Add a GitHub handle (or exchange age keys)    | Invite via dashboard                                         |
| Merge conflicts              | N/A                             | N/A — `.env.keys` is the shared secret, not the file     | No built-in merge driver (Clef is a third-party option)     | Built-in merge driver with `ours`/`theirs`              | N/A — cloud-managed                                          |
| Best suited for              | Solo hackathon, no real secrets | Solo devs and small teams wanting encrypted `.env` syntax | K8s / GitOps teams already on cloud KMS                    | Small-to-mid teams who want secrets to live in Git      | Orgs that want a GUI, audit logs, and a budget               |

**Where EnvSeal genuinely wins:** it's the only option here that's both free *and* branch-aware *and* lives inside Git without asking you to trust a third-party server. For a small team, that combination is hard to beat.

**Where EnvSeal is honestly not the best fit:** no web dashboard, no built-in audit trail, no non-technical UI. If your team includes people who won't touch a terminal, or you need compliance-grade access logs, use Doppler or Infisical. If you're already deep in Kubernetes and cloud KMS, SOPS is the more natural fit.

For a typical student or small-team codebase, the trade-off is easy: you're giving up a GUI you probably wouldn't use anyway, in exchange for something free, offline, and native to the Git workflow you're already using.

---

## Command reference

<details>
<summary><strong>Core commands</strong></summary>

| Command     | Usage                                                              | Description                                            |
| ----------- | ------------------------------------------------------------------ | ------------------------------------------------------ |
| `init`      | `envseal init [--local] [--git] [-r RECIPIENT]`                    | Initialize a project or global vault.                  |
| `git-setup` | `envseal git-setup [--init]`                                       | Register the Git merge driver and pre-commit shield.   |
| `set`       | `envseal set [-g GROUP] [-t TAG] KEY`                              | Store a secret (prompts without echoing input).        |
| `get`       | `envseal get [-g GROUP] [-t TAG] [--token TOK] KEY`                | Print one decrypted value.                             |
| `run`       | `envseal run [-g GROUP] [-t TAG] [--token TOK] -- CMD`             | Run a command with secrets injected (alias: `exec`).   |
| `load`      | `envseal load [-g GROUP] [-t TAG] [--token TOK] [KEYS...]`         | Print shell export statements for `eval`.              |
| `list`      | `envseal list [-g GROUP] [-t TAG]`                                 | List key names without revealing values (alias: `ls`). |
| `link`      | `envseal link GROUP`                                               | Bind a global vault group to the current directory.    |
| `remove`    | `envseal remove [-g GROUP] [-t TAG] [--force] [KEY]`               | Delete a key, tag, or group (alias: `rm`).             |
| `clear`     | `envseal clear`                                                    | Wipe cached master keys from the OS keyring session.   |
| `edit`      | `envseal edit [-g GROUP] [-t TAG]`                                 | Edit key/value pairs in your default editor.           |

</details>

<details>
<summary><strong>Access &amp; CI</strong></summary>

| Command         | Usage                                                  | Description                                                  |
| --------------- | ------------------------------------------------------ | ------------------------------------------------------------ |
| `recipient id`  | `envseal recipient id`                                 | Print your local public identity key.                        |
| `recipient add` | `envseal recipient add <@user \| KEY \| FILE>`         | Authorize a collaborator.                                    |
| `recipient ls`  | `envseal recipient ls`                                 | List authorized keys.                                        |
| `recipient rm`  | `envseal recipient rm <NAME \| INDEX \| KEY>`          | Revoke access and re-encrypt the vault.                      |
| `token`         | `envseal token [-t TAG] [-o PATH] [--exp S] [KEYS...]` | Mint a scoped, offline CI token.                             |
| `rotate`        | `envseal rotate`                                       | Rotate the encryption key, invalidating all existing tokens. |
| `import`        | `envseal import [-t TAG] PATH`                         | Import variables from an existing `.env` file.               |
| `export`        | `envseal export [-t TAG] [-o PATH] [KEYS...]`          | Decrypt to a `.env` file with strict `0600` permissions.     |

</details>

<details>
<summary><strong>Global flags</strong></summary>

- `-e, --env <PROFILE>` — target a specific profile file (e.g. `-e staging` loads `.staging.envseal`)
- `-G, --global` — target the system-wide vault
- `--no-env` — disable reading fallback identity keys from `ENVSEAL_IDENTITY`

</details>

**Most common day-to-day commands:**

```bash
# See what keys exist (never shows values)
envseal list
envseal list --tag staging

# One-off peek at a single value (use sparingly)
envseal get DATABASE_URL

# Import an existing .env you already have
envseal import .env

# Export only the keys you need for a temporary script
envseal export -o /tmp/temp.env DATABASE_URL STRIPE_SECRET

# Load into the current shell (prefer `run` for most workflows)
eval "$(envseal load)"
```

---

## Handling merge conflicts

EnvSeal registers as a native Git merge driver, so most merges resolve silently in the background. If two branches change the *same* variable to *different* values, it stops and asks you to choose:

```bash
# Keep the current branch's values
git -c envseal.merge.strategy=ours merge feature-branch

# Accept the incoming branch's values
git -c envseal.merge.strategy=theirs merge feature-branch
```

For CI runners that need a fixed, non-interactive rule:

```bash
git config envseal.merge.strategy theirs
```

**Tip:** After a successful merge you can always verify the resulting vault with:

```bash
envseal list
envseal run -- printenv | grep -E 'DATABASE|STRIPE|API'
```

(The `printenv` version only works inside `envseal run`, so the values never leak into your interactive shell.)

---

## Optional shell integration

`envseal run -- <CMD>` is the recommended usage since secrets only exist for the life of that process. If you'd rather load variables into your interactive shell session, add one of these:

<details>
<summary><strong>Bash / Zsh</strong> (~/.bashrc, ~/.zshrc)</summary>

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

</details>

<details>
<summary><strong>Fish</strong> (~/.config/fish/config.fish)</summary>

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

</details>

<details>
<summary><strong>PowerShell</strong> ($PROFILE)</summary>

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

</details>

**Warning about `envseal load`:** once variables are in your interactive shell, they stay there until you `unset` them or close the terminal. Prefer `envseal run -- ...` for almost every real workflow.

---

## Troubleshooting

- **`Access Denied: Identity not authorized for this environment`** — your key isn't registered in this vault yet. Ask a teammate with access to run `envseal recipient add` for you.

- **`SEAL TAMPERED: Ed25519 signature verification failed`** — the `.envseal` file was edited or corrupted outside the tool. Restore it with `git checkout -- .envseal`.

- **`Token scope mismatch`** — the token was minted for a different tag than the one you're running against. Re-mint it for the correct tag.

- **`Token expired`** — generate a new one with `envseal token`.

- **`Decryption failed for 'KEY'. Token is revoked or invalid`** — the vault's key was rotated after this token was issued. Re-mint it.

- **"No group linked to current directory"** — run `envseal link <GROUP>` to associate this directory with a group in your global vault.

- **"I forgot my private key and I'm the only recipient"** — see "The deal" section above. This is not a bug EnvSeal can fix; it's a backup problem.

- **`@teammate` recipient add fails** — the teammate doesn't have SSH keys on GitHub. Ask them to run `envseal recipient id` and send you the age key, then add it with `envseal recipient add "age1..."`.

**More common situations:**

- **Command not found after install** — restart your terminal or run `hash -r` (bash/zsh) so the new binary is picked up.
- **Permission denied on `/usr/local/bin`** — the install script falls back to `~/.local/bin`; make sure that directory is on your `PATH`.
- **Pre-commit hook not firing** — confirm you ran `envseal git-setup` inside the actual Git repository, not just in a parent folder.
- **Secrets not appearing after branch switch** — double-check that the tag name exactly matches the branch name (including any `/` characters).

---

## Upcoming features

- **Local Proxy Injection** — Injects credentials directly into outbound network traffic via a local proxy, preventing third-party packages or memory-dump exploits from exposing raw secrets in process memory.

---

## Contributing

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI

cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Pull requests are welcome. Please open an issue first for any larger design changes so we can discuss direction before you invest a lot of time. Keep the zero-trust, offline-first philosophy intact — no cloud services, no telemetry, no "phone home" features.

---

## Uninstall

**Linux & macOS**

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/uninstall.sh | bash
```

Or remove the binary manually:

```bash
rm -f /usr/local/bin/envseal ~/.local/bin/envseal
```

**Windows (WinGet)**

```bash
winget uninstall --id viswajith275.envseal -e
```

After uninstalling you may also want to remove any leftover `.envseal` files from your projects and clear the OS keyring cache with `envseal clear` (if the binary is still briefly available).

---

## FAQ

**Q: Can I use EnvSeal with Docker / Docker Compose?**

A: Yes. Build your image normally, then at runtime:

```bash
envseal run -- docker compose up
```

Or inject only the keys you need into the container environment.

**Q: Does it work with monorepos?**

A: Yes. You can keep one `.envseal` at the root or use the `-e` / profile mechanism for per-package vaults.

**Q: What happens if two people add different secrets at the same time?**

A: The Git merge driver usually resolves it automatically. If they both changed the *same* key, you'll be prompted to pick one side.

**Q: Can I still keep a local `.env` for personal overrides?**

A: Yes, but EnvSeal's pre-commit hook will block you from committing it. Treat personal overrides as truly local and never stage them.

**Q: What if my teammate doesn't have SSH keys on GitHub?**

A: `envseal recipient add @handle` will fail. Ask them to run `envseal recipient id`, which generates an age key for them. They send you the output, you add it with `envseal recipient add "age1..."`. Same result, one extra paste.

---

## License

MIT

---

Your secrets already live in the repo. They're just not encrypted yet.

Go seal them.
