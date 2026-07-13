mod cli;
mod utils;
mod commands;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()>{
    let clis = cli::Cli::try_parse().unwrap();
 
    match clis.command {
        cli::Commands::Init => commands::init::cmd_init(),
        cli::Commands::Set { key } => commands::set::cmd_set(&key),
        cli::Commands::Get { key } => commands::get::cmd_get(&key),
        cli::Commands::Load { keys } => commands::load::cmd_load(&keys),
        cli::Commands::Remove { key } => commands::remove::cmd_remove(&key),
}
}