# Security Policy

## Supported versions

Only the latest release of EnvSeal is actively supported with security fixes.

| Version | Supported |
| ------- | --------- |
| 6.1.x   | ✅        |
| < 6.1   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:
https://github.com/viswajith275/EnvSeal-CLI/security/advisories/new

If you can't use GitHub advisories, open a normal issue titled
`SECURITY: <short description>` with no technical details, and I'll reach
out to move the conversation somewhere private.

I aim to acknowledge reports within 72 hours and to publish a fix or a
mitigation plan within 14 days for issues that affect the confidentiality
of stored secrets. There is no bug bounty — this is a solo project — but
I'll credit you in the release notes if you want.

## Audit status

**EnvSeal has not been independently audited.** It is a solo project and
has not undergone a third-party security review. If your threat model
requires an audit before adoption, EnvSeal is not ready for you yet.

## Threat model

### What EnvSeal protects against

- **A leaked Git repository.** The vault (`*.envseal`) is encrypted for
  its recipients. Someone who clones the repo without a recipient's
  private key cannot read the secrets.
- **A stolen laptop without the identity key.** If the identity file
  (`~/.ssh/id_ed25519` or the age identity) is not on the stolen device,
  the vault is not readable.
- **Unauthorized recipients accessing future commits.** Revoking a
  recipient re-encrypts the vault and prevents them from decrypting any
  commit made after the revocation.
- **Accidental plaintext commits.** The pre-commit shield blocks staged
  `.env`, `.env.local`, and `.env.staging` files from being committed.

### What EnvSeal does not protect against

- **A compromised host that holds your identity key.** If an attacker has
  access to your machine and your identity file, they can decrypt the
  vault. EnvSeal cannot defend against an attacker who already has your
  private key.
- **Old commits that were decrypted before a recipient was removed.**
  Git history is permanent. Anyone who cloned the repo earlier still has
  the old encrypted commits and may still hold the key that decrypts them.
  Revocation is not retroactive.
- **A token payload with a bypassed clock check.** The `--exp` flag on
  CI tokens is enforced by the CLI at runtime, not by cryptography. An
  attacker with the raw token payload could bypass it. See the
  [README](README.md) section "The deal" for the full explanation.
- **Losing your own identity key.** There is no recovery mechanism.
  Back up your key outside the repo.

### Cryptographic primitives

- **Age** for symmetric encryption of the vault.
- **Ed25519** for signing the vault and verifying integrity.
- **Standard SSH keys** as an identity source, resolved through GitHub
  when adding a recipient by handle.

EnvSeal does not invent cryptographic primitives. It uses `age` and
`ed25519-dalek`, and it does not implement its own cipher.

## Scope

Reports are in scope if they affect:

- The confidentiality of stored secrets
- The integrity of the vault (undetected tampering)
- The recipient access model
- The pre-commit shield or merge driver

Reports are out of scope if they are:

- About the lack of an audit (documented above)
- About the CLI-enforced token expiry (documented above)
- About the inability to recover a lost identity key (documented above)
- About the offline nature of the tool

## Thank you

If you find something, thank you for telling me instead of publishing it.
Small projects live and die on whether people report issues responsibly.
