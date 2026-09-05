use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn find_repo_root() -> Option<PathBuf> {
    // path from git binary
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        if output.status.success() {
            let root_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !root_str.is_empty() {
                return Some(PathBuf::from(root_str));
            }
        }
    }

    // fallback: traversing to top till a .git file is find
    let mut current = env::current_dir().ok()?;
    loop {
        let git_path = current.join(".git");
        if git_path.exists() {
            return Some(current);
        }
        if !current.pop() {
            break;
        }
    }

    // returns null if any of them didnt work (.git file doesnt exist)
    None
}

pub fn sync_repo_git_conf(init_git: bool) -> Result<()> {
    // find repo path and create a .git folder accordingly
    let repo_root: PathBuf = match find_repo_root() {
        Some(root) => root,
        None => {
            if init_git {
                let cur_dir =
                    std::env::current_dir().context("Failed to get current working directory")?;

                let status = std::process::Command::new("git")
                    .current_dir(&cur_dir)
                    .arg("init")
                    .status()
                    .context("Failed to execute 'git init'. Is git installed in PATH?")?;

                if !status.success() {
                    anyhow::bail!("'git init' exited with non-zero status.");
                }

                eprintln!(
                    "[git] initialized a new repository at {}",
                    cur_dir.display()
                );

                cur_dir
            } else {
                anyhow::bail!(
                        "Not a git repository (or any parent directory), Run with '--init' to initialize a new repository, or run inside an existing one!!"
                    );
            }
        }
    };

    // merge driver
    let _ = Command::new("git")
        .current_dir(&repo_root)
        .args([
            "config",
            "--local",
            "merge.envseal.name",
            "envseal 3-way cryptographic merge driver",
        ])
        .output();
    let _ = Command::new("git")
        .current_dir(&repo_root)
        .args([
            "config",
            "--local",
            "merge.envseal.driver",
            "envseal merge --base %O --ours %A --theirs %B",
        ])
        .output();

    let attributes_path = repo_root.join(".gitattributes");

    let existing_content = fs::read_to_string(&attributes_path).unwrap_or_default();
    let has_envseal_rule = existing_content
        .lines()
        .any(|line| line.trim().starts_with("*.envseal") && line.contains("merge=envseal"));
    if !has_envseal_rule {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&attributes_path)
            .with_context(|| format!("Failed to open '{}'", attributes_path.display()))?;

        let mut rule = String::new();
        if !existing_content.is_empty() && !existing_content.ends_with('\n') {
            rule.push('\n');
        }

        rule.push_str("*.envseal merge=envseal\n");
        file.write_all(rule.as_bytes())?;
        eprintln!("[git] registered merge attributes for '*.envseal'");
    }

    let gitignore_path = repo_root.join(".gitignore");
    let existing_ignore = fs::read_to_string(&gitignore_path).unwrap_or_default();

    let lock_rule = ".envseal*.lock";
    if !existing_ignore.lines().any(|line| line.trim() == lock_rule) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gitignore_path)?;
        let mut rule = String::new();
        if !existing_ignore.is_empty() && !existing_ignore.ends_with('\n') {
            rule.push('\n');
        }
        rule.push_str(&format!("{lock_rule}\n"));
        file.write_all(rule.as_bytes())?;
        eprintln!("[git] added '{lock_rule}' to .gitignore to keep your workspace clean!!");
    }

    // hook for checking .env files and plain secrets
    let hooks_dir = repo_root.join(".git").join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    let existing_hook = fs::read_to_string(&hook_path).unwrap_or_default();

    if !existing_hook.contains("envseal pre-commit hook") {
        fs::create_dir_all(&hooks_dir)?;
        let hook_content = r#"#!/bin/sh
    # envseal pre-commit hook: prevent committing unsealed secrets and .env files

    # Reject staged plaintext .env files (allow .envseal files)
    staged_env=$(git diff --cached --name-only --diff-filter=ACM | grep -E '(^|/)\.env(\.[^/]+)?$' | grep -v '\.envseal')
    if [ -n "$staged_env" ]; then
        echo "[envseal] COMMIT REJECTED: Staged plaintext .env file(s) detected:" >&2
        echo "$staged_env" | sed 's/^/  - /' >&2
        echo "[envseal] Use 'envseal run' or encrypt secrets into '.envseal' instead." >&2
        exit 1
    fi
    "#;
        if existing_hook.is_empty() {
            fs::write(&hook_path, hook_content)?;
        } else {
            let mut file = OpenOptions::new().append(true).open(&hook_path)?;
            let snippet = hook_content
                .strip_prefix("#!/bin/sh\n")
                .unwrap_or(hook_content);
            file.write_all(format!("\n{snippet}").as_bytes())?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755));
        }
        eprintln!(
            "[git] installed pre-commit secret shield in '{}'",
            hook_path.display()
        );
    }

    Ok(())
}
