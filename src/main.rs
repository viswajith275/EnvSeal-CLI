mod cli;
mod commands;
mod utils;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let clis = cli::Cli::parse();
    match clis.command {
        cli::Commands::Init => commands::init::cmd_init(),
        cli::Commands::Set { group, tag, key } => {
            commands::set::cmd_set(group.as_deref(), tag.as_deref(), &key)
        }
        cli::Commands::Get { group, tag, key } => {
            commands::get::cmd_get(group.as_deref(), tag.as_deref(), &key)
        }
        cli::Commands::Load { group, tag, keys } => {
            commands::load::cmd_load(group.as_deref(), tag.as_deref(), &keys)
        }
        cli::Commands::Remove { group, tag, key } => {
            commands::remove::cmd_remove(group.as_deref(), tag.as_deref(), key.as_deref())
        }
        cli::Commands::List { group, tag } => {
            commands::list::cmd_list(group.as_deref(), tag.as_deref())
        }
        cli::Commands::Run {
            group,
            tag,

            cmd_args,
        } => commands::run::cmd_run(
            group.as_deref(),
            tag.as_deref(),
            cmd_args.iter().map(|s| s.as_str()).collect(),
        ),
        cli::Commands::Import { group, tag, path } => {
            commands::import::cmd_import(group.as_deref(), tag.as_deref(), &path)
        }
        cli::Commands::Export { group, tag, keys } => commands::export::cmd_export(
            group.as_deref(),
            tag.as_deref(),
            keys.iter().map(|s| s.as_str()).collect(),
        ),
        cli::Commands::Link { group } => commands::link::cmd_link(&group),
        cli::Commands::Protag { group, tag } => {
            commands::protag::cmd_protag(group.as_deref(), &tag)
        }
        cli::Commands::Clear => commands::clear::cmd_clear(),
    }
}
