mod cli;
mod commands;
mod utils;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let clis = cli::Cli::parse();

    match clis.command {
        cli::Commands::Init => commands::init::cmd_init(),
        cli::Commands::Set { group, tag, key } => commands::set::cmd_set(&group, &tag, &key),
        cli::Commands::Get { group, tag, key } => commands::get::cmd_get(&group, &tag, &key),
        cli::Commands::Load { group, tag, keys } => commands::load::cmd_load(&group, &tag, &keys),
        cli::Commands::Remove { group, tag, key } => {
            commands::remove::cmd_remove(&group, &tag, &key)
        }
        cli::Commands::List { group, tag } => commands::list::cmd_list(&group, &tag),
        cli::Commands::Run {
            group,
            tag,
            cmd_args,
        } => commands::run::cmd_run(&group, &tag, &cmd_args),
        cli::Commands::Import { group, tag, path } => {
            commands::import::cmd_import(&group, &tag, &path)
        }
        cli::Commands::Export { group, tag, keys } => {
            commands::export::cmd_export(&group, &tag, &keys)
        }
        cli::Commands::Link { group } => commands::link::cmd_link(group),
    }
}
