use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "envseal",
    about = "An encrypted vault for your API keys and secrets, because `.env` files have never once kept a secret.
"
)]
#[command(version = "v5.0.0")]
#[command(propagate_version = true)]
pub struct Cli {
    /// Target a specific local environment profile (e.g., 'prod' targets '.prod.envseal')
    #[arg(short, long, global = true)]
    pub env: Option<String>,

    /// Force operations on the global system vault, bypassing any local .envseal files
    #[arg(short = 'G', long, global = true)]
    pub global: bool,

    /// The subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new encrypted vault (seal) to store secrets
    ///
    /// Creates a new secure seal in the default location, encrypted by a master password.
    /// NOTE: This must be run before using any other envseal commands.
    Init {
        /// To initialise a local enviornment (e.g, '.envseal' file in current directory)
        #[arg(short, long)]
        local: bool,
    },

    /// Clear the Master Password from the local session cache
    ///
    /// Securely flushes the cached master password from memory. You will be
    /// prompted to re-enter your password on your next envseal operation.
    Clear,

    /// Link a variable group to the current working directory
    ///
    /// Binds a specific group of variables to the current directory so you
    /// don't have to manually specify `--group` in future commands run from here.
    Link {
        /// The name of the group to link to this directory
        group: String,
    },

    /// Create or manage protected tags within a group
    ///
    /// Tags allow you to version or environment-scope your variables (e.g., 'dev', 'prod').
    /// Protected tags require specific confirmation to modify or delete.
    Protag {
        /// The group to apply the tag to (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The name of the protected tag to create
        tag: String,
    },

    /// Export secrets to a standard .env file
    ///
    /// Decrypts and writes the specified keys (or an entire group/tag) to a
    /// local .env file. Useful for integrating with legacy tools that require
    /// unencrypted files on disk.
    Export {
        /// The group to export from (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag to export from
        #[arg(short, long)]
        tag: Option<String>,
        /// Output path of .env file defaults to .env in current directory
        #[arg(short, long)]
        output_path: Option<String>,
        /// Path to a file containing the zero-trust execution token
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Specific keys to export (exports all if empty)
        keys: Vec<String>,
    },

    /// Import variables from an existing .env file into the vault
    ///
    /// Reads an unencrypted .env file and securely stores its key-value pairs
    /// into the specified group or tag inside your encrypted seal.
    Import {
        /// The group to import variables into (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag to import variables into
        #[arg(short, long)]
        tag: Option<String>,
        /// Path to the .env file to read from
        path: String,
    },

    /// Securely store or update a secret key
    ///
    /// Prompts for a value and encrypts it under the given key. Automatically
    /// creates the specified group or tag if it doesn't already exist.
    Set {
        /// The group to store the key in (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag to scope the key to
        #[arg(short, long)]
        tag: Option<String>,
        /// The name of the environment variable (e.g., API_KEY)
        key: String,
    },

    /// Retrieve and decrypt the value of a specific key
    ///
    /// Fetches a single encrypted variable, decrypts it, and prints it to standard
    /// output. Useful for piping specific secrets into other scripts.
    Get {
        /// The group to fetch the key from (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,

        /// The tag to fetch the key from
        #[arg(short, long)]
        tag: Option<String>,
        /// Path to a file containing the zero-trust execution token
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// The name of the key to retrieve
        key: String,
    },

    /// Source variables directly into your current shell session
    ///
    /// Decrypts variables and outputs shell-compatible export commands. To use this,
    /// evaluate it in your shell (e.g., 'eval $(envseal load)') normally automatically done by a function added to the shell config.
    /// Warning!! For isolated execution, 'envseal run' is highly recommended instead.
    Load {
        /// The group to load variables from (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag to load variables from
        #[arg(short, long)]
        tag: Option<String>,
        /// Path to a file containing the zero-trust execution token
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Specific keys to load (loads all if empty)
        keys: Vec<String>,
    },

    /// Delete a secret key, tag, or entire group
    ///
    /// Permanently removes the specified key from the vault. If no key is provided,
    /// it deletes the entire group or tag. This action cannot be undone.
    Remove {
        /// The group to remove data from (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag to remove data from
        #[arg(short, long)]
        tag: Option<String>,
        /// The specific key to delete (deletes the group/tag if omitted)
        key: Option<String>,
    },

    /// View all stored keys and vault structure
    ///
    /// Displays a list of your configured groups, tags, and secret keys without
    /// revealing their decrypted values to the screen.
    List {
        /// Filter the list by a specific group (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// Filter the list by a specific tag
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Execute a command with decrypted variables injected into its environment
    ///
    /// Spawns a child process and injects the specified group's secrets securely
    /// into its environment. Secrets never touch the disk and your main shell
    /// remains perfectly clean.
    Run {
        /// The group of variables to inject (uses linked group if omitted)
        #[arg(short, long)]
        group: Option<String>,
        /// The tag of variables to inject
        #[arg(short, long)]
        tag: Option<String>,
        /// Path to a file containing the zero-trust execution token
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// The command and its arguments to execute (e.g., `npm start`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd_args: Vec<String>,
    },
    /// Generate a zero-trust Bearer Token for CI/CD or offline execution
    ///
    /// Generates a read only token with specified scopes and access to gain more
    /// control on who can access what. No more leakage of master password by sharing
    /// it with everyone
    Token {
        /// The group of which is included in scope
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// The tag which is included in scope
        #[arg(short = 't', long)]
        tag: Option<String>,
        /// Name given to token (creater name / reason for creating token)
        #[arg(short = 'n', long, default_value = "envseal-token")]
        name: String,
        /// Description of token (whats the scope, what it is used for etc...)
        #[arg(short = 'd', long)]
        desc: Option<String>,
        /// Securely write the token directly to a file (restricted permissions)
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Expiration time in seconds (Added to the current time!!)
        #[arg[long]]
        exp: Option<u64>,
        /// Specific keys from the scope only
        keys: Vec<String>,
    },
    /// Rotate the Data Encryption Key (DEK) for a specific scope
    ///
    /// Invalidates all existing zero-trust tokens for the target scope by re-encrypting
    /// the variables with a freshly generated cryptographic key.
    Rotate {
        #[arg(short, long)]
        group: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
    },
}
