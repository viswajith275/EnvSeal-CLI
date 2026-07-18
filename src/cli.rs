use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envseal", about = "Encrypted Environment Manager")]
#[command(version = "v2.0.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize and create a seal encrypted with a "Master Password" to store secrets
    Init,

    /// Link a specific group to current working directory
    Link { group: String },

    /// Export specified keys into a .env file, optionally scoped by group or tag
    Export {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        keys: Vec<String>,
    },

    /// Import variables from a given .env file path into the specified group or tag
    Import {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        path: String,
    },

    /// Set or update the value of a given key (creates the group/tag if it doesn't exist)
    Set {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: String,
    },

    /// Retrieve the stored value for a specific key
    Get {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: String,
    },

    /// Load specified keys (or an entire group) into the current terminal environment. (Note: 'run' is recommended for most use cases)
    Load {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        keys: Vec<String>,
    },

    /// Remove a specific key, or an entire group/tag if no key is specified
    Remove {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: Option<String>,
    },

    /// List all keys, optionally filtered by a specific group or tag
    List {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Execute a command in a child process with the environment variables loaded (keeps current session clean)
    Run {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd_args: Vec<String>,
    },
}
