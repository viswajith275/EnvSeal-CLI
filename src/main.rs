mod cli;
mod commands;
mod utils;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let clis = cli::Cli::parse();

    match clis.command {
        cli::Commands::Init => commands::init::cmd_init(),
        cli::Commands::Set {
            group_name,
            tag,
            key,
        } => commands::set::cmd_set(&key, &group_name),
        cli::Commands::Get {
            group_name,
            tag,
            key,
        } => commands::get::cmd_get(&key, &group_name),
        cli::Commands::Load {
            group_name,
            tag,
            keys,
        } => commands::load::cmd_load(&keys, &group_name),
        cli::Commands::Remove {
            group_name,
            tag,
            key,
        } => commands::remove::cmd_remove(&key, &group_name),
        cli::Commands::List { group_name, tag } => commands::list::cmd_list(&group_name),
        cli::Commands::Run {
            group_name,
            tag,
            cmd_args,
        } => commands::run::cmd_run(cmd_args, &group_name),
        cli::Commands::Import {
            group_name,
            tag,
            path,
        } => commands::import::cmd_import(&group_name, &path),
        cli::Commands::Export {
            group_name,
            tag,
            keys,
        } => commands::export::cmd_export(&keys, &group_name),
    }
}
