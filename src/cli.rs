use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envfuse", about = "Encrypted local API key manager")]
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
    }
}