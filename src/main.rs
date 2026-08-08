mod cli;
mod commands;
mod utils;

use anyhow::{anyhow, Result};
use clap::Parser;

fn main() -> Result<()> {
    let clis = cli::Cli::parse();
    let global = clis.global;
    let pref = clis.env.as_deref().filter(|s| !s.is_empty());

    if global && pref.is_some() {
        return Err(anyhow!(
                "Conflict: Cannot use --env with --global.\n\
                UseCase: The global vault uses 'Tags' to manage environments (e.g., `envseal protag prod`), \
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
    match clis.command {
        cli::Commands::Init { local } => commands::init::cmd_init(local, global, pref),
        cli::Commands::Set { group, tag, key } => {
            commands::set::cmd_set(group.as_deref(), tag.as_deref(), &key, global, pref)
        }
        cli::Commands::Get { group, tag, key } => {
            commands::get::cmd_get(group.as_deref(), tag.as_deref(), &key, global, pref)
        }
        cli::Commands::Load { group, tag, keys } => {
            commands::load::cmd_load(group.as_deref(), tag.as_deref(), &keys, global, pref)
        }
        cli::Commands::Remove { group, tag, key } => commands::remove::cmd_remove(
            group.as_deref(),
            tag.as_deref(),
            key.as_deref(),
            global,
            pref,
        ),
        cli::Commands::List { group, tag } => {
            commands::list::cmd_list(group.as_deref(), tag.as_deref(), global, pref)
        }
        cli::Commands::Run {
            group,
            tag,
            cmd_args,
        } => commands::run::cmd_run(
            group.as_deref(),
            tag.as_deref(),
            cmd_args.iter().map(|s| s.as_str()).collect(),
            global,
            pref,
        ),
        cli::Commands::Import { group, tag, path } => {
            commands::import::cmd_import(group.as_deref(), tag.as_deref(), &path, global, pref)
        }
        cli::Commands::Export {
            group,
            tag,
            keys,
            output_path,
        } => commands::export::cmd_export(
            group.as_deref(),
            tag.as_deref(),
            keys.iter().map(|s| s.as_str()).collect(),
            global,
            pref,
            output_path.as_deref(),
        ),
        cli::Commands::Link { group } => commands::link::cmd_link(&group, global, pref),
        cli::Commands::Protag { group, tag } => {
            commands::protag::cmd_protag(group.as_deref(), &tag, global, pref)
        }
        cli::Commands::Clear => commands::clear::cmd_clear(global, pref),
    }
}
