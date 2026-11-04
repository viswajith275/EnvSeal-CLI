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
[![Featured on VibeLeaderboard](https://img.shields.io/endpoint?url=https%3A%2F%2Fwww.vibeleaderboard.ai%2Fapi%2Fv1%2Fapps%2F809f8383-8172-424b-aa45-1afca134a053%2Fbadge)](https://www.vibeleaderboard.ai/app/809f8383-8172-424b-aa45-1afca134a053)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> **Git for secrets.** An offline, Git-native secrets manager for environment variables and the files that go with them — TLS certificates, service-account JSON, keystores, kubeconfigs. Built on SSH and Age. Your vault is a file in your repo — encrypted for the people who need it, switched by branch, and mergeable like code.

EnvSeal isn't a cloud secrets manager. It isn't just an encrypted `.env` file. It's a file in your repository that holds every secret your app needs to start — environment variables and the certificates, service-account JSON, and kubeconfigs that never fit in `.env`. It travels with `git pull`, follows your branch, resolves with `git merge`, and is reviewed in pull requests like everything else you commit.

No cloud. No accounts. No shared master password. Just Git, public keys, and a CLI that stays out of your way.

Secrets aren't always strings. TLS certificates, service-account JSON, `.p12` keystores, SSH keys, and kubeconfigs can live in the same vault. At runtime, EnvSeal decrypts each one to a private temporary file and hands your process the path — not a shared drive, not a wiki attachment, not a "temporary" commit from three years ago.

---

## Install

```bash
# Linux & macOS
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash

# Windows
winget install --id viswajith275.envseal -e

# From source
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI

cargo build --release
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

That's the entire setup. Once you've added them as a recipient (below), your teammate pulls, runs `envseal run -- npm start`, and it works — same keys, correct branch, zero DMs.

**Already have a `.env`?** Import it in one step:

```bash
envseal import .env
# the original plaintext file is left for you to delete
```

**Already have a secret that's a file?** Seal it the same way:

```bash
envseal set TLS_CERT --file ./certs/server.pem --env-var TLS_CERT_PATH
envseal run -- node server.js
# $TLS_CERT_PATH → a private temp file that disappears when the process exits
```

`--env-var` defaults to the key name, so `envseal set GCP_SA --file ./gcp.json` gives your process `$GCP_SA`.

**Add a teammate — two paths, depending on their setup:**

```bash
# Path A — they have SSH keys on GitHub:
# EnvSeal fetches their public SSH keys automatically.
envseal recipient add @their-github-handle

# Path B — they don't have SSH keys set up:
# They run `envseal recipient id`, which creates or reuses their local identity key.
# They send you the output. You add it manually.
envseal recipient add "age1ql3z7hjy54pw3hy..."
```

Both work. Path A is one command with zero manual key exchange. Path B is still a single command — you just paste a key instead of a handle.

---

## Real examples

**Switching branches:**
```bash
$ git checkout staging
$ envseal run -- npm start
> app@1.0.0 start
> node server.js
listening on :3000
```
No `--tag` needed: `envseal run` reads your current Git branch and applies the matching tag (here, `staging`) before starting the child process.

**Accidentally staging a `.env`:**
```
$ git add .
$ git commit -m "wip"
[envseal] COMMIT REJECTED: Staged plaintext .env file(s) detected:
  - .env
[envseal] Use 'envseal run' or encrypt secrets into '.envseal' instead.
```

**Someone leaves the team:**
```
$ envseal recipient rm 1
Removed recipient 'age1...'. Vault re-encrypted.

$ envseal rotate
re-encrypting vault and rotating DEK...
successfully rotated DEK. All previous tokens are now invalid.
```
Removing the recipient re-wraps the vault key for everyone else. `rotate` is the step that changes the data key, so do it immediately — and rotate the real credentials too, because old commits and copied keys are still out there.

**App exits:**
```
$ envseal run -- npm start
> app@1.0.0 start
> node server.js
listening on :3000
^C
```
Text secrets were injected into the child process's environment; file secrets were temp paths that EnvSeal overwrote and deleted on exit.

**Mixing global and local vaults:**
```bash
# Pull only DATABASE_URL from the global vault
envseal run --override DATABASE_URL -- npm start

# Overlay everything from the global vault (global wins)
envseal run --with-global -- npm start

# Use a specific global group and tag
envseal run --with-global --global-group shared-aws --global-tag prod -- ./deploy.sh
```

**Bulk editing secrets in your editor:**
```bash
# Open the base secrets for the current group in $EDITOR
envseal edit

# Edit a specific tag
envseal edit --tag staging

# Edit a specific group in the global vault
envseal edit --group myapp
```
The `edit` command decrypts the selected secrets into a temporary file, opens it in your default editor, and writes only the net changes back into the encrypted vault. The temporary file is overwritten with zeros and deleted on exit. This is ideal for bulk updates or when you prefer a native editor over repeated `set`/`rm` commands.

**A certificate that never touches a shared folder:**
```
$ envseal set KUBECONFIG --file ~/.kube/prod.yaml --env-var KUBECONFIG
sealed file 'KUBECONFIG' in group 'project' (local seal)

$ envseal run -- kubectl get pods
# KUBECONFIG points at a private temp copy, overwritten and deleted when kubectl exits
```
No USB stick. No "download this from the wiki." No plaintext kubeconfig sitting in a synced folder with production cluster access.

---

## Why not SOPS? Why not dotenvx? Why not Doppler?

**SOPS** encrypts files. It's a great tool for a different job: encrypting config at rest. What it doesn't give you is a branch-aware, Git-native workflow or a merge driver. It can inject secrets with `sops exec-env` / `exec-file`, but you wire that workflow yourself. Every new teammate means a manual age key exchange and a `sops updatekeys` run.

**dotenvx** encrypts your `.env` file and lets you commit it safely. It's a solid tool with real encryption, rotation, and git-diff audit. The difference is architectural: dotenvx uses a **single shared private key per environment**, so "who has access" is the same question as "who has the key." It also stops at environment strings — a certificate or kubeconfig still has to live somewhere else. EnvSeal seals the vault to **individual recipients** and handles both, so adding a teammate is a Git commit and removing one is a commit plus `envseal rotate` — not a key redistribution.

**Doppler / Infisical** are excellent products. They're primarily cloud services with dashboards, audit logs, and per-seat pricing (both offer self-hosting, with supported/air-gapped deployments on paid tiers). If your team needs those things, use them. Infisical's MIT-licensed core is free to self-host; supported air-gapped deployments are an Enterprise offering.

EnvSeal is for the team in between: small, already on Git, tired of being the unofficial IT department, and still passing certificates around because they don't fit in a `.env`.

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

- **The secret that isn't a string.**
  Your TLS certificate, service-account JSON, SSH key, and kubeconfig don't fit in `.env`, so they live in a shared drive, a wiki attachment, or a synced folder with production access. Someone rotates one and the next person spends an afternoon discovering the app was reading a stale copy. `.env` was never designed for files — so the files quietly became everyone's problem.

None of these are exotic. They're what happens when secrets live outside version control and the code that needs them doesn't. The fix isn't a better `.env` file. It's putting the vault somewhere Git already knows how to move.

---

## How EnvSeal fixes this

EnvSeal keeps secrets *inside* your repository, but encrypted — so Git can do what Git is good at (syncing state across a team) without ever exposing plaintext.

- **One teammate adds a key, everyone gets it.** Push your changes, and the encrypted vault updates for the whole team. No more "can someone send me the `.env`" messages.
- **Secrets follow your branch automatically.** Check out `staging` and run `envseal run`; EnvSeal applies the `staging` tag automatically. Check out `main`, and it switches back.
- **Nothing plaintext touches chat, and nothing lingers on disk.** Text secrets are decrypted in memory and injected into the child process's environment. File secrets decrypt to a private temp file that is overwritten and deleted when the process exits.
- **A pre-commit hook stops the panic push.** If you (or a sleepy teammate) accidentally try to commit a raw `.env` file, EnvSeal blocks it before it reaches Git history.
- **Migration is one command.** Already have a `.env`? `envseal import .env` brings it into the vault. Need a temporary plaintext file for a legacy tool? `envseal export` writes it with strict `0600` permissions.
- **Files are secrets too.** Certificates, service-account JSON, keystores, and kubeconfigs get sealed alongside your environment variables. At runtime they're decrypted to private temp files and referenced by path — so your app gets what it needs without a shared drive or another copy in chat.
- **Interactive shell when you want it.** `envseal load` prints export statements so you can `eval "$(envseal load)"` — useful for debugging, while `envseal run` remains the safe default for everyday work.
- **Global and local vaults can be mixed.** Use `--override` to pull specific keys from your global vault, or `--with-global` to overlay everything from it.

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

Tokens scope file secrets the same way: list `TLS_CERT` in the token and the runner can read that file key, nothing else. You can also pass the token string (or a path to it) through the `ENVSEAL_TOKEN` environment variable.

### Rotating keys and revoking tokens

Group member leaves the project, or a laptop gets compromised? Rotate the encryption key and every previously issued token can no longer decrypt the current vault:

```bash
envseal rotate
```

### Pre-commit shield

`envseal git-setup` installs a hook that blocks staged `.env` files — `.env` itself and variants like `.env.local` and `.env.staging` — while letting `.env.example` / `.sample` / `.template` / `.dist` and the encrypted `.envseal` file through.

### Multiple local profiles

Need separate vaults for different environments without relying only on branch tags? Use `-e` / `--env`:

```bash
envseal -e staging set DATABASE_URL
envseal -e prod run -- npm start
# targets .staging.envseal / .prod.envseal
```

### Global vault override

Mix secrets from your system-wide global vault into a local project at runtime. These flags are available on `run`, `load`, and `export`.

```bash
# Pull only the named keys from the global vault
envseal run --override DATABASE_URL,STRIPE_KEY -- npm start

# Overlay all keys from the global vault (global takes precedence)
envseal run --with-global -- npm start

# Specify which global group and tag to use
envseal run --with-global --global-group shared-aws --global-tag prod -- ./deploy.sh
```

`--override` and `--with-global` are mutually exclusive. If neither is given, the local vault is used alone. `--global-group` defaults to the directory's linked group, and `--global-tag` defaults to `base`.

### Interactive editor

Bulk-edit secrets using your familiar `$EDITOR` instead of repeated `set`/`rm` commands. EnvSeal decrypts the selected secrets into a temporary file, opens it in your preferred editor (`$EDITOR` / `$VISUAL`, falling back to `nano` on Unix or `notepad` on Windows), and writes only the net changes back into the vault. The temp file is overwritten with zeros and deleted on exit.

```bash
# Edit base secrets for the current/linked group
envseal edit

# Edit a specific tag
envseal edit --tag staging

# Edit a specific group
envseal edit --group myapp
```

File secrets appear read-only in that buffer, so a casual text edit can't corrupt them. Update them with `envseal set KEY --file PATH`, or remove them with `envseal remove KEY`.

### Also included

- **In-memory decryption for text, overwritten temp files for files** — text secrets are decrypted in memory and injected into the child process you launch with `envseal run`. File secrets are written to a private temp file, then overwritten and deleted when that process exits. When the process ends, no plaintext file is left behind.
- **Sealed files, not just strings** — `envseal set TLS_CERT --file ./certs/server.pem --env-var TLS_CERT_PATH` seals any file up to 10 MB: certificates, service-account JSON, `.p12` keystores, SSH keys, kubeconfigs. At runtime, `run` decrypts it to a private `0600` temp path (`0700` if the source was executable), preserves the extension, and overwrites/deletes it on exit. `get KEY -o PATH` writes it back out — new files get the same mode, while overwriting an existing path keeps that file's current permissions. Piped stdout gets the raw bytes.
- **Compression that earns its keep** — file contents are zstd-compressed only when that makes them smaller, so text-like configs shrink and incompressible binaries are stored as-is.
- **File-aware tooling** — in an interactive terminal, `list` marks file entries as `[file -> $ENV_VAR]`; `edit` shows them read-only; `export` and `load` are text-only and skip them. Use `run` or `get -o` for files.
- **Shell loading** — `envseal load` prints export statements so you can `eval "$(envseal load)"` when you intentionally want secrets in your interactive shell.
- **Easy migration** — `envseal import` brings an existing `.env` into the vault; `envseal export` writes selected keys back out with strict `0600` permissions.
- **Zero cloud dependency** — the core workflow works on a plane, behind a corporate firewall, or on a completely air-gapped machine. The only network call is `recipient add @user`, which fetches that user's public GitHub keys.
- **Cross-platform** — same commands on Linux, macOS, and Windows; Unix file modes like `0600`/`0700` apply on Unix only.
- **Merge-driver aware** — concurrent edits to different secrets usually resolve automatically; conflicting edits on the *same* key stop with a named conflict you resolve with `ours` or `theirs` instead of a binary mess.

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

Once a directory is linked to a group with `envseal link`, plain `envseal` commands run from inside that directory resolve against the linked global group automatically — as long as there's no local `.envseal` in that directory or its parents.

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

- **Removing someone from the recipient list is not the same as rotating the data key.**
  `envseal recipient rm <name|index|key>` removes them from future vault envelopes, but it keeps the same data key. If they unlocked the vault before, they still hold that key and can decrypt *future* commits as well as old ones. Run `envseal rotate` immediately after removing someone: that generates a new data key and re-encrypts the current vault, so their old copy is useless for anything new. Even then, Git history is permanent — anyone who cloned earlier still has old encrypted commits and could decrypt those with the old key. If someone leaves the team under bad terms, rotate the actual credentials (database password, API keys) too. Removing access is taking away their house key after they've already made a copy.

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
- Never commit raw token files or private keys. The pre-commit shield only guards `.env` files, so this one is on your habits.

---

## How it compares

Pricing and capabilities verified as of November 2026.

Every tool below solves the same underlying problems — accidental commits, environment switching, team access, and the certificate that never fit in a `.env` — just through a different mechanism. The table shows *how* each one addresses the same concern, so you can judge which trade-off fits your team. If your team needs a dashboard or audit log, use Doppler or Infisical. If you're deep in Kubernetes and cloud KMS, SOPS fits your pipeline better. EnvSeal is for the team in between.

|                              | Plain `.env`                    | dotenvx                                                  | Mozilla SOPS                                                | **EnvSeal**                                             | Doppler / Infisical                                          |
| ---------------------------- | ------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------ |
| Cost                         | Free                            | Free; Member $5/mo, Business $90/mo                       | Free                                                        | Free, no account needed                                 | Doppler: free for 3 users, $8/mo per additional user. Infisical: free up to 5 identities, Pro $23/identity/mo ($20 annual) |
| Works offline                | Yes                             | Yes — local CLI                                          | Yes with age. Cloud KMS modes need connectivity to encrypt/decrypt | Yes, fully                                       | Cloud-first; offline use needs a prior cache. Infisical's MIT core is free to self-host; supported air-gapped is Enterprise |
| Environment / branch switching | Manual file swap (`.env`, `.env.staging`) | Manual `-f .env.production` at invocation           | Per-file, driven by CI env vars or shell aliases            | `envseal run` reads the current branch and applies a matching tag | `--config` flag at runtime, or a project setting in the dashboard |
| Preventing accidental commits | Relies on `.gitignore` discipline | Optional `dotenvx precommit` hook                     | `.gitignore` + decrypt only in CI; nothing plaintext is committed | Built-in pre-commit shield blocks staged `.env` files (examples pass) | Nothing to commit — secrets never touch the repo             |
| Team onboarding              | Manual file sharing             | Share `.env.keys` (one key per environment)              | Add each age key to `.sops.yaml`, run `sops updatekeys`     | Add a GitHub handle, or paste an age key                | Invite via dashboard; SSO available on paid tiers            |
| Merge behavior               | Git text merge                  | Git text merge on the encrypted file                     | Git text merge on YAML/JSON; conflicts need decrypt → merge → re-encrypt | Native merge driver with `ours` / `theirs`              | N/A — cloud-managed, no file to merge                        |
| Personal / local overrides   | `.env.local` (gitignored)       | `.env.local` overrides `.env`                            | Separate `.sops.yaml` per developer, or shell env vars      | Global vault + `--override` / `--with-global`           | Personal configs in dashboard, or `--personal` flag          |
| Files / certificates         | Strings only                    | Strings only                                             | Encrypts any file, but you wire injection yourself          | Seals files and injects a private temp path at runtime  | File/mount support varies by plan and platform               |
| Best suited for              | Solo hackathon, no real secrets | Solo devs and small teams wanting encrypted `.env` syntax | K8s / GitOps teams already on cloud KMS                    | Small-to-mid teams who want env vars and file secrets to live in Git | Orgs that want a GUI, audit logs, and a budget               |

**Where EnvSeal genuinely wins:** it's free, branch-aware, lives inside Git, and injects both environment variables and sealed files at runtime without asking you to trust a third-party server. For a small team, that combination is hard to beat.

**Where EnvSeal is honestly not the best fit:** no web dashboard, no built-in audit trail, no non-technical UI. If your team includes people who won't touch a terminal, or you need compliance-grade access logs, use Doppler or Infisical. If you're already deep in Kubernetes and cloud KMS, SOPS is the more natural fit.

**A note on dotenvx and SOPS in this table:** dotenvx does more than a row can capture — it has real encryption, rotation, and git-diff audit. The architectural difference is that dotenvx uses a single shared private key per environment, while EnvSeal seals to individual recipients. SOPS is a mature, widely-used tool with strong KMS integrations and solid file encryption; the gap is that recipient management, merge behavior, and runtime injection are left for you to wire up, which is a deliberate design choice for GitOps pipelines, not a shortcoming.

For a typical student or small-team codebase, the trade-off is easy: you're giving up a GUI you probably wouldn't use anyway, in exchange for something free, offline, and native to the Git workflow you're already using.

---

## Command reference

<details>
<summary><strong>Core commands</strong></summary>

| Command     | Usage                                                              | Description                                            |
| ----------- | ------------------------------------------------------------------ | ------------------------------------------------------ |
| `init`      | `envseal init [--local] [--git] [-r RECIPIENT]`                    | Initialize a project or global vault.                  |
| `git-setup` | `envseal git-setup [--init]`                                       | Register the Git merge driver and pre-commit shield.   |
| `set`       | `envseal set [-g GROUP] [-t TAG] KEY [--file PATH] [--env-var VAR]` | Store a secret (prompts without echoing input), or seal a file. |
| `get`       | `envseal get [-g GROUP] [-t TAG] [--token TOK] [-o PATH] KEY`      | Print one decrypted value, or write a sealed file back to disk. |
| `run`       | `envseal run [-g GROUP] [-t TAG] [--token TOK] [--clear] [--override K1,K2 \| --with-global] -- CMD` | Run a command with secrets injected (alias: `exec`). |
| `load`      | `envseal load [-g GROUP] [-t TAG] [--token TOK] [--override K1,K2 \| --with-global] [KEYS...]` | Print shell export statements for `eval`.              |
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
| `recipient rm`  | `envseal recipient rm <NAME \| INDEX \| KEY>`          | Remove a recipient and re-wrap the vault key. Run `rotate` to change the data key. |
| `token`         | `envseal token [-t TAG] [-o PATH] [--exp S] [KEYS...]` | Mint a scoped, offline CI token.                             |
| `rotate`        | `envseal rotate`                                       | Rotate the encryption key, invalidating all existing tokens. |
| `import`        | `envseal import [-t TAG] PATH`                         | Import variables from an existing `.env` file.               |
| `export`        | `envseal export [-t TAG] [-o PATH] [--override K1,K2 \| --with-global] [KEYS...]` | Decrypt to a `.env` file with strict `0600` permissions. |

</details>

<details>
<summary><strong>Global flags</strong></summary>

- `-e, --env <PROFILE>` — target a specific profile file (e.g. `-e staging` loads `.staging.envseal`)
- `-G, --global` — target the system-wide vault
- `--no-env` — disable reading fallback identity keys from `ENVSEAL_IDENTITY` and `ENVSEAL_IDENTITY_FILE`
</details>

<details>
<summary><strong>Override flags</strong></summary>
 
- `--override <KEY1,KEY2>` — pull only the named keys from the global vault (conflicts with `--with-global`)
- `--with-global` — overlay all keys from the global vault (global wins on collision; conflicts with `--override`)
- `--global-group <GROUP>` — which group inside the global vault to use (defaults to the directory's linked group)
- `--global-tag <TAG>` — optional tag inside that global group (defaults to `base`)

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

**File secrets in one place:**

```bash
# Seal a certificate, key, or config file
envseal set TLS_CERT --file ./certs/server.pem --env-var TLS_CERT_PATH

# See the binding without revealing contents
envseal list                       # TLS_CERT [file -> $TLS_CERT_PATH]

# Write the decrypted file back out (new files get 0600/0700) when a tool needs a real path
envseal get TLS_CERT -o ./server.pem

# Normal runtime: a private temp path, overwritten and deleted on exit
envseal run -- node server.js
```

---

## Handling merge conflicts

EnvSeal registers as a native Git merge driver, so most merges resolve silently in the background. If two branches change the *same* variable to *different* values, the merge stops with a named conflict; resolve it by re-running with a strategy:

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

- **`@teammate` recipient add fails** — the teammate doesn't have SSH keys on GitHub. Ask them to run `envseal recipient id` and send you the public identity key, then add it with `envseal recipient add "age1..."` (or the SSH key they sent).

- **`--override` and `--with-global` used together** — they are mutually exclusive. Pick one: `--override` to pull specific keys, or `--with-global` to overlay everything.

**More common situations:**

- **Command not found after install** — restart your terminal or run `hash -r` (bash/zsh) so the new binary is picked up.
- **Permission denied on `/usr/local/bin`** — the install script falls back to `~/.local/bin`; make sure that directory is on your `PATH`.
- **Pre-commit hook not firing** — confirm you ran `envseal git-setup` inside the actual Git repository, not just in a parent folder.
- **Secrets not appearing after branch switch** — double-check that the tag name exactly matches the branch name (including any `/` characters).
- **`envseal load` or `envseal export` skipped a file key** — file secrets are only injected by `run`, or extracted with `get -o PATH`. Plaintext `.env` output is text-only.
- **`envseal get FILE_KEY` printed a size summary instead of the file** — that's the terminal safety check. Add `-o PATH` to write it to disk, or pipe stdout to receive the raw bytes.

---

## Upcoming features

- **Local Proxy Injection** — Injects credentials directly into outbound network traffic via a local proxy, preventing third-party packages or memory-dump exploits from exposing raw secrets in process memory.

---

## Security

EnvSeal has not been independently audited. The threat model, cryptographic
primitives, and known limitations are documented in [`SECURITY.md`](SECURITY.md).

If you find a vulnerability, please open a
[security advisory](https://github.com/viswajith275/EnvSeal-CLI/security/advisories/new)
rather than a public issue.

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

A: Yes. Keep one `.envseal` at the root, or put a separate `.envseal` in each package — EnvSeal uses the nearest one. Use the `-e` / profile mechanism when you want multiple vaults side by side.

**Q: What happens if two people add different secrets at the same time?**

A: The Git merge driver usually resolves it automatically. If they both changed the *same* key, the merge stops with a conflict; resolve it with `git -c envseal.merge.strategy=ours merge …` or `theirs`.

**Q: Can I still keep a local `.env` for personal overrides?**

A: Yes, but EnvSeal's pre-commit hook will block you from committing it. Treat personal overrides as truly local and never stage them. If you want a cleaner path for personal tokens, use the global vault with `--override` or `--with-global`.

**Q: What if my teammate doesn't have SSH keys on GitHub?**

A: `envseal recipient add @handle` will fail. Ask them to run `envseal recipient id`, which creates (or reuses) their local identity. They send you the output, you add it with `envseal recipient add "age1..."`. Same result, one extra paste.

**Q: Can I store TLS certificates, SSH keys, service-account JSON, or kubeconfigs?**
A: Yes. Those are file secrets:

```bash
envseal set TLS_CERT --file ./certs/server.pem --env-var TLS_CERT_PATH
envseal run -- node server.js
```

`run` decrypts the file to a private temp path, sets `$TLS_CERT_PATH` to it, and overwrites/deletes it when the process exits. Use `envseal get TLS_CERT -o ./server.pem` if a tool needs the file at a fixed path. `export` and `load` are text-only: `export` skips file secrets with a warning, and `load` warns if you explicitly name one.

**Q: What's the difference between `--override` and `--with-global`?**

A: `--override KEY1,KEY2` pulls **only** the named keys from the global vault. `--with-global` overlays **all** keys from the global vault, with global values winning on collision. They are mutually exclusive.

---

## License

MIT

---

Your secrets already live in the repo. They're just not encrypted yet.

Go seal them.
