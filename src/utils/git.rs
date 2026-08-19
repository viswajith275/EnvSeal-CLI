use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn find_repo_root() -> Option<PathBuf> {
    // Path from git binary
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

    // Fallback: traversing to top till a .git file is find
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
    // Find repo path and create a .git folder accordingly
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

    // diff driver and disable plaintext disk caching
    let _ = Command::new("git")
        .current_dir(&repo_root)
        .args(["config", "--local", "diff.envseal.textconv", "envseal diff"])
        .output();
    let _ = Command::new("git")
        .current_dir(&repo_root)
        .args(["config", "--local", "diff.envseal.cachetextconv", "false"])
        .output();

    let attributes_path = repo_root.join(".gitattributes");

    let existing_content = fs::read_to_string(&attributes_path).unwrap_or_default();

    let has_envseal_rule = existing_content.lines().any(|line| {
        line.trim().starts_with("*.envseal")
            && line.contains("merge=envseal")
            && line.contains("diff=envseal")
    });

    if !has_envseal_rule {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&attributes_path)
            .with_context(|| format!("Failed to open '{}'", attributes_path.display()))?;

        let mut rule = String::new();
        if !existing_content.is_empty() && !existing_content.ends_with('\n') {
            rule.push('\n'); // creating new line
        }
        rule.push_str("*.envseal merge=envseal diff=envseal\n");

        file.write_all(rule.as_bytes())?;
        eprintln!("[git] registered merge and diff attributes for '*.envseal'");
    }

    Ok(())
}
