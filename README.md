# EnvSeal-CLI
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

**Your `.env` file, but it actually survives a group project.**

EnvSeal is an offline, zero-trust secrets manager built on standard SSH and Age encryption. Instead of a plaintext `.env` sitting on your laptop (and nowhere else), your secrets live inside an encrypted `.envseal` file that you commit straight to Git. They travel with the repo, switch automatically based on your branch, and decrypt only in memory for people you've explicitly authorized.

---

## The problem, if you've ever worked on a team project

If you've built anything with more than one contributor, one of these has happened to you:

- **"Wait, it works on my machine." **
Someone adds a new API key to their local `.env`, gets the feature working, and pushes the code. Nobody else has that key. The app breaks for everyone else, and you spend the next hour in a group chat asking "does anyone know what `PAYMENT_API_KEY` is supposed to be?"

- **The `.env` file that never gets shared **
`.env` is gitignored for good reason, but that also means it never reaches your teammates automatically. So it gets passed around as a WhatsApp message, a Discord DM, or a copy-pasted block in a shared Google Doc — sitting there in plaintext, forever, in someone's chat history.

- **Wrong branch, wrong database **
You switch from `main` to a `staging` or `experiment` branch to test something, but your `.env` doesn't know that. You're now running experimental code against production data, or worse, testing against a database that doesn't have the tables your new branch expects.

- **The 2 AM `git add .` **
It's late, the deadline is tomorrow, and `git add .` scoops up a `.env` file along with everything else. Now there's a real API key sitting in your Git history — and if the repo is public, bots are already scanning for it.

None of these are exotic problems. They're just what happens when secrets live outside version control but the code that needs them doesn't.

---

## How EnvSeal fixes this

EnvSeal keeps secrets *inside* your repository, but encrypted — so Git can do what Git is good at (syncing state across a team) without ever exposing plaintext.

- **One teammate adds a key, everyone gets it.** Push your changes, and the encrypted vault updates for the whole team. No more "can someone send me the `.env`" messages.

- **Secrets follow your branch automatically.** Check out `staging`, and EnvSeal loads the `staging`-tagged secrets. Check out `main`, and it switches back. No manual swapping, no stale config.

- **Nothing plaintext ever touches disk or chat.** Secrets decrypt directly into the memory of the process you're running, and disappear when it exits.

- **A pre-commit hook stops the panic push.** If you (or a sleepy teammate) accidentally try to commit a raw `.env` file, EnvSeal blocks it before it reaches Git history.

In short: EnvSeal is what happens when you get tired of being the unofficial IT department for your own group project.

**Bonus:** Because the vault is just a file in the repo, your secrets inherit all the normal Git workflows you already use — pull requests, code review, `git blame`, and history. You can see *when* a secret was added or changed without ever seeing the value itself.

---

## Installation

### Linux & macOS

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh | bash
```

To review the script first (always a good habit before piping into `bash`):

```bash
curl -sSfL https://raw.githubusercontent.com/viswajith275/EnvSeal-CLI/master/scripts/install.sh -o install.sh
less install.sh
bash install.sh
```

### Windows (WinGet)

```bash
winget install --id viswajith275.envseal -e
```

### From Source (via Cargo)

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI
cargo build --release
cp target/release/envseal /usr/local/bin/
```

**Verify the install**

```bash
envseal --version
envseal --help
```

If the binary is not found, make sure `~/.local/bin` or `/usr/local/bin` is on your `PATH`. On most systems the install script handles this automatically.

---

## Quick Start: setting this up for a team project

### 1. Initialize the vault

```bash
envseal init --local
envseal git-setup
```

`git-setup` registers a Git merge driver (so two people editing secrets on different branches doesn't turn into a manual merge nightmare) and installs the pre-commit hook that blocks raw `.env` files.

### 2. Add your teammates

Everyone gets access without ever seeing a shared master password:

```bash
# Pull their public key straight from GitHub
envseal recipient add @teammate-github-handle

# Or add a raw public key they send you
envseal recipient add "age1ql3z7hjy54pw3hy... # priya"
```

### 3. Store your secrets, scoped by branch if needed

```bash
# Shared across every branch
envseal set DATABASE_URL
envseal set STRIPE_PUBLIC_KEY

# Only loaded when the 'staging' branch is checked out
envseal set --tag staging DATABASE_URL
```

### 4. Run your app — secrets included

```bash
envseal run -- npm start
```

Push your changes. Your teammate pulls, runs `envseal run -- npm start`, and it just works — same keys, correct branch, zero DMs required. It's almost suspicious how little drama is involved.

**Pro tip for the first day:** After `envseal init --local`, immediately commit the new `.envseal` file (and the updated `.gitignore` / `.gitattributes` that `git-setup` creates). That way the rest of the team can pull and start using the vault without any extra setup steps.

---

## Core Features

### Git-Native Branch Binding

`envseal run` checks `git rev-parse --abbrev-ref HEAD` behind the scenes. If a stored tag matches your current branch name, it's applied automatically:

```bash
git checkout feature/stripe-v2
envseal set --tag feature/stripe-v2 STRIPE_SECRET
envseal run -- cargo test # uses this branch's secret + falls back to base
```

### Frictionless Onboarding

New contributor joins the project? They run:

```bash
envseal recipient id
```

...send you the output, you run `envseal recipient add`, and they're in. No re-typing shared passwords into a dozen laptops.

### Scoped Tokens for CI/CD

Never paste your personal SSH or Age key into a CI runner. Mint a short-lived, narrowly scoped token instead:

```bash
envseal token --tag prod -o ./ci.token --exp 3600 STRIPE_SECRET DATABASE_URL
envseal run --token ./ci.token -- npm run migrate
```

### Instant Revocation

Group member leaves the project, or a laptop gets compromised? Rotate the encryption key and every previously issued token becomes unreadable ciphertext instantly:

```bash
envseal rotate
```

### Pre-Commit Shield

`envseal git-setup` installs a hook that blocks staged `.env`, `.env.local`, and `.env.staging` files from ever being committed, while letting the encrypted `.envseal` file through.

**Additional quality-of-life features you get for free:**

- **In-memory only decryption** — plaintext secrets exist only inside the child process you launch with `envseal run`. When that process exits, the secrets are gone.
- **Zero cloud dependency** — works on a plane, behind a corporate firewall, or on a completely air-gapped machine.
- **Cross-platform** — same binary behavior on Linux, macOS, and Windows.
- **Merge-driver aware** — concurrent edits to different secrets usually resolve automatically; conflicting edits on the *same* key surface a clean choice instead of a binary conflict.

---

## Things Worth Knowing (Read Before You Trust Any Encryption Tool Blindly)

Cryptography is very good at math and very bad at knowing whether you actually meant to leave the front door open. A few honest caveats:

**Removing someone doesn't erase what they already saw.**
`envseal recipient rm <name>` stops a person from decrypting *future* commits, but Git history is permanent — anyone who cloned the repo earlier still has old encrypted commits and could decrypt them with a key they already hold. If someone leaves the team under bad terms, rotate the actual credentials (database password, API keys) too, not just the vault. Removing their access is not a memory wipe; it's just taking away their house key after they've already made a copy.

**`envseal rotate` protects the future, not the past — same issue as removing a recipient.**
Rotating generates a fresh encryption key and re-encrypts the *current* state of the vault, which is exactly what you want after a token or laptop is compromised. But it doesn't retroactively re-encrypt old Git commits. Those historical `.envseal` snapshots stay in your Git history, encrypted under the *old* key. If a leaked token ever let someone extract the underlying derived key material, they could, in theory, still use it to decrypt those old commits — rotation doesn't undo that. The only thing that actually neutralizes a leaked secret is changing the secret itself. So the real rule is: **if a token or key leaks, rotate the vault *and* go rotate the actual API keys or database passwords at the source.** `envseal rotate` is a good first move, not an undo button.

**Token expiry is enforced by the CLI, not by cryptography.**
The `--exp` flag is checked at runtime by EnvSeal itself. Because everything is offline, there's no server refusing an expired token — a sufficiently determined attacker with the raw token payload could bypass the clock check. If a CI runner is ever compromised, don't wait for the token to expire: rotate the vault and the underlying secrets immediately.

**If you're a solo developer and you're your only recipient, you are also your own single point of failure.**
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

## How It Compares

No secrets tool is perfect for every setup. Here's an honest look:

```
|                              | Plain `.env`                    | dotenvx                                        | Mozilla SOPS                                     | **EnvSeal**                                             | Doppler / Infisical                                     |
| ---------------------------- | ------------------------------- | ---------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------- |
| Cost                         | Free                            | Free / paid tiers                              | Free                                             | Free, no account needed                                 | $18–30/seat/month                                       |
| Works offline                | Yes                             | Yes                                            | Mostly                                           | Yes, fully                                              | No — needs their cloud                                  |
| Auto-switches per Git branch | No                              | No                                             | No                                               | Yes                                                     | Only via dashboard config                               |
| Stops accidental commits     | No                              | Partially                                      | No                                               | Yes, built-in hook                                      | Yes (via CLI wrapper)                                   |
| Team onboarding              | Manual file sharing             | Manual file sharing                            | Manual key exchange                              | Add a GitHub handle                                     | Invite via dashboard                                    |
| Best suited for              | Solo hackathon, no real secrets | Small projects wanting encrypted `.env` syntax | Large Kubernetes/GitOps setups tied to cloud KMS | Small-to-mid teams who want secrets to just live in Git | Orgs that want a GUI, audit logs, and don't mind paying |
```

**Where EnvSeal genuinely wins:** it's the only option here that's both free *and* branch-aware *and* lives inside Git without asking you to trust a third-party server. For a student project or small team repo, that combination is hard to beat.

**Where EnvSeal is honestly not the best fit:** it has no web dashboard, no built-in audit trail of who accessed what and when, and no non-technical UI — if your team includes people who won't touch a terminal, or you need compliance-grade access logs, Doppler or Infisical will serve you better. If you're already deep in Kubernetes and cloud KMS, SOPS is probably the more natural fit than bolting EnvSeal onto that pipeline.

For a typical student or small-team codebase, though, the trade-off is easy: you're giving up a GUI you probably wouldn't use anyway, in exchange for something free, offline, and native to the Git workflow you're already using.

Besides, a monthly subscription for secrets management is a tough sell when your team's entire budget is instant noodles and shared Wi-Fi.

---

## Command Reference

### Core

```
| Command     | Usage                                                  | Description                                            |
| ----------- | ------------------------------------------------------ | ------------------------------------------------------ |
| `init`      | `envseal init [--local] [--git] [-r RECIPIENT]`        | Initialize a project or global vault.                  |
| `git-setup` | `envseal git-setup [--init]`                           | Register the Git merge driver and pre-commit shield.   |
| `set`       | `envseal set [-g GROUP] [-t TAG] KEY`                  | Store a secret (prompts without echoing input).        |
| `get`       | `envseal get [-g GROUP] [-t TAG] [--token TOK] KEY`    | Print one decrypted value.                             |
| `run`       | `envseal run [-g GROUP] [-t TAG] [--token TOK] -- CMD` | Run a command with secrets injected (alias: `exec`).   |
| `list`      | `envseal list [-g GROUP] [-t TAG]`                     | List key names without revealing values (alias: `ls`). |
| `remove`    | `envseal remove [-g GROUP] [-t TAG] [--force] [KEY]`   | Delete a key, tag, or group (alias: `rm`).             |
| `clear`     | `envseal clear`                                        | Wipe cached master keys from the OS keyring session.   |
```

### Access & CI

```
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
```

### Global Flags

- `-e, --env <PROFILE>` — target a specific profile file (e.g. `-e staging` loads `.staging.envseal`)
- `-G, --global` — target the system-wide vault
- `--no-env` — disable reading fallback identity keys from `ENVSEAL_IDENTITY`

**Quick examples of the most common day-to-day commands:**

```bash
# See what keys exist (never shows values)
envseal list
envseal list --tag staging

# One-off peek at a single value (use sparingly)
envseal get DATABASE_URL

# Import an existing .env you already have
envseal import .env
# (the original plaintext file is left for you to delete)

# Export only the keys you need for a temporary script
envseal export -o /tmp/temp.env DATABASE_URL STRIPE_SECRET
```

---

## Handling Merge Conflicts

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

## Optional Shell Integration

`envseal run -- <CMD>` is the recommended usage since secrets only exist for the life of that process. If you'd rather load variables into your interactive shell session, add one of these:

**Bash / Zsh** (`~/.bashrc`, `~/.zshrc`)

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

**Fish** (`~/.config/fish/config.fish`)

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

**PowerShell** (`$PROFILE`)

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

**Warning about `envseal load`:** once the variables are in your interactive shell they stay there until you `unset` them or close the terminal. Prefer `envseal run -- ...` for almost every real workflow.

---

## Troubleshooting

- **`Access Denied: Identity not authorized for this environment`** — your key isn't registered in this vault yet. Ask a teammate with access to run `envseal recipient add` for you.

- **`SEAL TAMPERED: Ed25519 signature verification failed`** — the `.envseal` file was edited or corrupted outside the tool. Restore it with `git checkout -- .envseal`.

- **`Token scope mismatch`** — the token was minted for a different tag than the one you're running against. Re-mint it for the correct tag.

- **`Token expired`** — generate a new one with `envseal token`.

- **`Decryption failed for 'KEY'. Token is revoked or invalid`** — the vault's key was rotated after this token was issued. Re-mint it.

- **"I forgot my private key and I'm the only recipient"** — see the section above titled "Read Before You Trust Any Encryption Tool Blindly." This one is not a bug EnvSeal can fix; it's a you problem, and unfortunately also a backup problem.

**More common situations:**

- **Command not found after install** — restart your terminal or run `hash -r` (bash/zsh) so the new binary is picked up.

- **Permission denied on `/usr/local/bin`** — the install script falls back to `~/.local/bin`; make sure that directory is on your `PATH`.

- **Pre-commit hook not firing** — confirm you ran `envseal git-setup` inside the actual Git repository, not just in a parent folder.

- **Secrets not appearing after branch switch** — double-check that the tag name exactly matches the branch name (including any `/` characters).

---

## Upcoming Features

* **Local Proxy Injection:** Injects credentials directly into outbound network traffic via a local proxy, preventing third-party packages or memory-dump exploits from exposing raw secrets in process memory.


---

## Contributing

```bash
git clone https://github.com/viswajith275/EnvSeal-CLI.git
cd EnvSeal-CLI

cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Pull requests are welcome. Please open an issue first for any larger design changes so we can discuss direction before you invest a lot of time. Keep the zero-trust, offline-first philosophy intact — no cloud services, no telemetry, no “phone home” features.

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

## License

MIT

---

## FAQ (quick answers to general questions)

**Q: Can I use EnvSeal with Docker / Docker Compose?**  
A: Yes. Build your image normally, then at runtime do something like:

```bash
envseal run -- docker compose up
```

or inject only the keys you need into the container environment.

**Q: Does it work with monorepos?**  
A: Yes. You can keep one `.envseal` at the root or use the `-e` / profile mechanism for per-package vaults.

**Q: What happens if two people add different secrets at the same time?**  
A: The Git merge driver usually resolves it automatically. If they both changed the *same* key, you’ll be prompted to pick one side.

**Q: Can I still keep a local `.env` for personal overrides?**  
A: Yes, but EnvSeal’s pre-commit hook will block you from committing it. Treat personal overrides as truly local and never stage them.

That’s everything. Go seal your secrets and stop babysitting `.env` files.
