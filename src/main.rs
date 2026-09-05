mod cli;
mod commands;
mod utils;

use anyhow::{anyhow, Ok, Result};
use clap::Parser;
use cli::{Cli, Commands};
use envseal::utils::git;

fn main() -> Result<std::process::ExitCode> {
    let cli = Cli::parse();
    let global = cli.global;
    let pref = cli.env.as_deref().filter(|s| !s.is_empty());
    let allow_env = !cli.no_env;

    if global && pref.is_some() {
        return Err(anyhow!(
            "Conflict: Cannot use --env with --global.\n\
             UseCase: The global vault uses 'Tags' to manage environments (e.g., 'envseal protag prod'), \
             whereas --env is strictly for managing multiple local files like .prod.envseal."
        ));
    }

    if let Some(name) = pref {
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!(
                "Invalid environment name: '{}'. Only alphanumeric characters, dashes, and underscores are allowed.",
                name
            ));
        }
    }

    match cli.command {
        Commands::Run {
            group,
            tag,
            cmd_args,
            token_file,
        } => {
            let code = commands::run::cmd_run(
                group.as_deref(),
                tag.as_deref(),
                cmd_args.iter().map(|s| s.as_str()).collect(),
                token_file.as_ref(),
                global,
                pref,
                allow_env,
            )?;
            return Ok(std::process::ExitCode::from(code as u8));
        }
        Commands::Init { local, git } => commands::init::cmd_init(local, global, pref, git)?,
        Commands::Set { group, tag, key } => commands::set::cmd_set(
            group.as_deref(),
            tag.as_deref(),
            &key,
            global,
            pref,
            allow_env,
        )?,
        Commands::Get {
            group,
            tag,
            key,
            token_file,
        } => commands::get::cmd_get(
            group.as_deref(),
            tag.as_deref(),
            &key,
            token_file.as_ref(),
            global,
            pref,
            allow_env,
        )?,
        Commands::Load {
            group,
            tag,
            keys,
            token_file,
        } => commands::load::cmd_load(
            group.as_deref(),
            tag.as_deref(),
            keys.iter().map(|s| s.as_str()).collect(),
            token_file.as_ref(),
            global,
            pref,
            allow_env,
        )?,
        Commands::Remove {
            group,
            tag,
            key,
            force,
        } => commands::remove::cmd_remove(
            group.as_deref(),
            tag.as_deref(),
            key.as_deref(),
            global,
            pref,
            force,
            allow_env,
        )?,
        Commands::List { group, tag } => {
            commands::list::cmd_list(group.as_deref(), tag.as_deref(), global, pref)?
        }
        Commands::Import { group, tag, path } => commands::import::cmd_import(
            group.as_deref(),
            tag.as_deref(),
            &path,
            global,
            pref,
            allow_env,
        )?,
        Commands::Export {
            group,
            tag,
            keys,
            output_path,
            token_file,
        } => commands::export::cmd_export(
            group.as_deref(),
            tag.as_deref(),
            keys.iter().map(|s| s.as_str()).collect(),
            token_file.as_ref(),
            global,
            pref,
            &output_path,
            allow_env,
        )?,
        Commands::Link { group } => commands::link::cmd_link(&group, global, pref, allow_env)?,
        Commands::Protag { group, tag } => {
            commands::protag::cmd_protag(group.as_deref(), &tag, global, pref, allow_env)?
        }
        Commands::Token {
            group,
            tag,
            name,
            desc,
            out,
            keys,
            exp,
        } => commands::token::cmd_token(
            group.as_deref(),
            tag.as_deref(),
            name.as_str(),
            desc.as_deref(),
            out.as_ref(),
            keys,
            exp,
            global,
            pref,
            allow_env,
        )?,
        Commands::Rotate { group, tag } => {
            commands::rotate::cmd_rotate(group.as_deref(), tag.as_deref(), global, pref, allow_env)?
        }
        Commands::Clear => commands::clear::cmd_clear(global, pref)?,
        Commands::Passwd => commands::passwd::cmd_passwd(global, pref, allow_env)?,
        Commands::Diff { file } => commands::diff::cmd_diff(&file, allow_env)?,
        Commands::Merge {
            base,
            ours,
            theirs,
            strategy,
        } => commands::merge::cmd_merge(&base, &ours, &theirs, &strategy)?,
        Commands::GitSetup { init } => {
            git::sync_repo_git_conf(init)?;
            println!("git configuration successfull!!");
        }
    }

    Ok(std::process::ExitCode::SUCCESS)
}
