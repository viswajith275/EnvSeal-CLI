use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envseal", about = "Encrypted Enviornment Manager")]
#[command(version = "v1.2.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize and create seal encrypted with "Master Password" to store secrets
    Init,
    ///[GROUP_NAME] > .env  Retrieve the enviornment variable into a .env file
    Link { group_name: String, path: String },
    Export {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        keys: Vec<String>,
    },
    ///[GROUP_NAME] [PATH_OF_.ENV]  Loads the variables in the .env to the specified group
    Import {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        path: String,
    },
    ///[GROUP_NAME] [KEY]   Set or Update a value of a given key in a group (Creates the group if it doesnt exists)
    Set {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: String,
    },
    ///[GROUP_NAME] [KEY]   Get the value of a given key in a group
    Get {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: String,
    },
    ///[GROUP_NAME] [KEYS..]    Load the given keys or group (if keys not given) into current terminal enviornment (Use run command for most usecases)
    Load {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        keys: Vec<String>,
    },
    ///[GROUP_NAME] [KEY]   Removes the given key or group (if key not specified)
    Remove {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        key: Option<String>,
    },
    ///[GROUP_NAME] List all keys in a group
    List {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
    },
    ///[GROUP_NAME] [COMMAND]   Loads the enviornment variables into a child process (not into current terminal session)
    Run {
        #[arg(short, long)]
        group_name: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd_args: Vec<String>,
    },
}
