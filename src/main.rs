mod cli;
mod utils;
mod commands;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()>{
    let clis = cli::Cli::try_parse();
    let clis = match clis {
        Ok(cli) => cli,
        Err(_) => panic!("Invalid command!"),
    };
 
    match clis.command {
        cli::Commands::Init => commands::init::cmd_init(),
        cli::Commands::Set { key } => commands::set::cmd_set(&key),
        cli::Commands::Get { key } => commands::get::cmd_get(&key),
        cli::Commands::Load { keys } => commands::load::cmd_load(&keys),
        cli::Commands::Remove { key } => commands::remove::cmd_remove(&key),
        cli::Commands::List => commands::list::cmd_list(),
        cli::Commands::Run { cmd_args } => commands::run::cmd_run(cmd_args),
    }
}