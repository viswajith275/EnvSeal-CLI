use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envseal", about = "Encrypted local API key manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}
 
#[derive(Subcommand)]
pub enum Commands {
    Init,
    Set {
        key: String,
    },
    Get {
        key: String,
    },
    Load {
        #[arg(required = true)]
        keys: Vec<String>,
    },
    Remove {
        key: String,
    },
    List,
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd_args: Vec<String>,
    },
}