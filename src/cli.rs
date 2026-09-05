use clap::{ArgAction, Parser, Subcommand, ValueEnum, ValueHint};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "envseal",
    about = "Encrypted vault for secrets and API keys stop committing plaintext .env files.",
    version = "v5.2.0",
    propagate_version = true
)]
pub struct Cli {
    /// Target a specific local environment profile (e.g., 'prod' -> '.prod.envseal')
    #[arg(short, long, global = true, value_name = "PROFILE")]
    pub env: Option<String>,

    /// Force operations on the global system vault instead of local .envseal files
    #[arg(short = 'G', long, global = true)]
    pub global: bool,

    /// Disable loading fallback passwords from environment variables
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub no_env: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum RecipientCommands {
    /// Print your local public recipient key (auto-generates if missing)
    #[command(alias = "id")]
    Identity,

    /// Add public key(s) from a key string, file path, or stdin ('-')
    Add {
        /// Recipient public key, path to key file, or '-' for stdin
        #[arg(default_value = "-")]
        target: String,
    },

    /// List all public keys authorized to unlock this vault
    #[command(alias = "ls")]
    List,

    /// Remove a recipient public key and re-encrypt the vault envelope
    #[command(alias = "rm")]
    Remove {
        /// Public key string to remove
        target: String,
    },
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage recipient public keys
    Recipient {
        #[command(subcommand)]
        action: RecipientCommands,
    },
    /// Initialize a new encrypted vault
    ///
    /// Creates an encrypted seal in the target location, configured with a master
    /// password and automatic Git merge/diff attributes.
    Init {
        /// Create a local vault ('.envseal') in the current directory
        #[arg(short, long)]
        local: bool,

        /// Automatically run 'git init' if not already in a Git repository
        #[arg(short, long)]
        git: bool,

        /// Target recipient of this file
        #[arg(short, long)]
        recipient: Option<String>,
    },

    /// Configure Git merge and diff drivers for envseal
    ///
    /// Configures custom diff and merge attributes so encrypted seals can be
    /// tracked in Git without merge conflicts corrupting the ciphertext.
    GitSetup {
        /// Initialize a git repository if one does not exist
        #[arg(short, long)]
        init: bool,
    },

    /// Clear the master password from the session cache
    ///
    /// Securely wipes the cached master key from memory, requiring password
    /// re-entry on the next operation.
    Clear,

    /// Link a variable group as default for the current directory
    ///
    /// Eliminates the need to pass `--group` on subsequent commands in this folder.
    Link {
        /// Name of the group to bind to this directory
        group: String,
    },

    /// Decrypt and export secrets to a standard .env file
    ///
    /// Writes unencrypted key-value pairs to disk for legacy tools that require
    /// plaintext files.
    Export {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Output path for the exported file
        #[arg(
            short,
            long,
            default_value = ".env",
            value_name = "PATH",
            value_hint = ValueHint::FilePath
        )]
        output_path: PathBuf,

        /// Offline token string, path to token file, or '-' for stdin
        #[arg(long)]
        token: Option<String>,

        /// Specific keys to export (exports all if omitted)
        keys: Vec<String>,
    },

    /// Import variables from an existing .env file into the vault
    Import {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Path to the .env file to import
        #[arg(value_hint = ValueHint::FilePath)]
        path: String,
    },

    /// Securely store or update a secret key
    ///
    /// Prompts for the value interactively or reads from stdin to avoid leaking
    /// secrets into shell history.
    Set {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Secret key name (e.g., STRIPE_SECRET_KEY)
        key: String,
    },

    /// Retrieve and decrypt a single key
    Get {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Offline token string, path to token file, or '-' for stdin
        #[arg(long)]
        token: Option<String>,

        /// Key name to retrieve
        key: String,
    },

    /// Print shell export commands for decrypted variables
    ///
    /// Intended for shell evaluation: `eval $(envseal load)`. For isolated
    /// execution without modifying shell state, prefer `envseal run`.
    Load {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Offline token string, path to token file, or '-' for stdin
        #[arg(long)]
        token: Option<String>,

        /// Specific keys to load (loads all if omitted)
        keys: Vec<String>,
    },

    /// Delete a secret key, tag, or entire group
    #[command(alias = "rm")]
    Remove {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag to remove
        #[arg(short, long)]
        tag: Option<String>,

        /// Bypass confirmation prompt
        #[arg(short, long)]
        force: bool,

        /// Specific key to delete (deletes whole group/tag if omitted)
        key: Option<String>,
    },

    /// List stored keys, groups, and tags without revealing secret values
    #[command(alias = "ls")]
    List {
        /// Filter by group (defaults to linked group if set)
        #[arg(short, long)]
        group: Option<String>,

        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Execute a command with decrypted secrets injected into its environment
    ///
    /// Spawns a child process with injected variables. Secrets never touch disk
    /// or persist in shell history.
    #[command(alias = "exec")]
    Run {
        /// Target group (defaults to linked group)
        #[arg(short, long)]
        group: Option<String>,

        /// Target tag within the group
        #[arg(short, long)]
        tag: Option<String>,

        /// Offline token string, path to token file, or '-' for stdin
        #[arg(long)]
        token: Option<String>,

        /// Command and arguments to execute (e.g., `npm start` or `-- python app.py`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd_args: Vec<String>,
    },

    /// Generate a scoped, read-only token for CI/CD or offline execution
    Token {
        /// Group to include in scope
        #[arg(short, long)]
        group: Option<String>,

        /// Tag to include in scope
        #[arg(short, long)]
        tag: Option<String>,

        /// Identifier for tracking token origin/purpose
        #[arg(short, long, default_value = "envseal-token")]
        name: String,

        /// Optional description of token usage scope
        #[arg(short, long)]
        desc: Option<String>,

        /// Write the generated token directly to a restricted-permission file
        #[arg(short, long, value_name = "PATH", value_hint = ValueHint::FilePath)]
        out: Option<PathBuf>,

        /// Token validity duration in seconds from creation
        #[arg(long, value_name = "SECONDS")]
        exp: Option<u64>,

        /// Restrict token to these specific keys
        keys: Vec<String>,
    },

    /// Rotate the Data Encryption Key (DEK) for a specific scope
    ///
    /// Re-encrypts secrets under a new key, immediately invalidating all existing
    /// zero-trust tokens issued for this scope.
    Rotate,

    /// Internal 3-way merge driver invoked by Git
    #[command(hide = true)]
    Merge {
        /// Ancestor file path (%O)
        #[arg(long, value_hint = ValueHint::FilePath)]
        base: PathBuf,

        /// Current branch file path (%A)
        #[arg(long, value_hint = ValueHint::FilePath)]
        ours: PathBuf,

        /// Incoming branch file path (%B)
        #[arg(long, value_hint = ValueHint::FilePath)]
        theirs: PathBuf,

        /// Conflict resolution strategy
        #[arg(long, value_enum, default_value_t = MergeStrategy::Fail)]
        strategy: MergeStrategy,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum MergeStrategy {
    Fail,
    Ours,
    Theirs,
}
