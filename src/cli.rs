//! Command-line interface definitions for ByteLock.
//!
//! This module defines the public CLI surface of ByteLock using `clap`.
//! It contains no application logic and exists solely to describe how
//! users interact with the program from the terminal.

use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(
    name = "bytelock",
    version = "0.1",
    about = "A minimal, local, encrypted password manager",
    long_about = r#"
ByteLock is a small, local-first password manager.

All secrets are encrypted using a master password and stored in a single
vault file on disk. ByteLock does not use the network, does not run
background services, and does not depend on external infrastructure.

Typical usage:
  bytelock init
  bytelock add github
  bytelock get github
  bytelock list
  bytelock passwd

Security model:
- A master password derives an encryption key using Argon2id
- All data is encrypted with XChaCha20-Poly1305
- No plaintext passwords are stored on disk
"#,
)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new vault
    ///
    /// This command creates a new vault file on disk and prompts
    /// for a master password. The master password is used to derive
    /// the encryption key for all stored entries.
    ///
    /// This should be the first command run when setting up ByteLock.
    Init,

    /// Add a new entry to the vault
    ///
    /// The password is read securely from the terminal, encrypted,
    /// and stored under the given name.
    ///
    /// By default, existing entries are not overwritten unless
    /// --force is specified.
    Add(AddArgs),

    /// Retrieve and display a stored password
    ///
    /// The password is decrypted in memory after verifying the
    /// master password. Use --copy to copy the password to the
    /// clipboard for a short time instead of printing it.
    Get {
        /// Name of the entry to retrieve
        name: String,

        /// Copy the password to the clipboard for 10 seconds
        #[arg(short, long)]
        copy: bool,
    },

    /// List all entry names in the vault
    ///
    /// This command only displays entry names, never passwords.
    /// The master password is still required.
    List,

    /// Remove an entry from the vault
    ///
    /// Permanently deletes the specified entry from the vault.
    /// This action cannot be undone.
    Remove {
        /// Name of the entry to remove
        name: String,
    },

    /// Update an existing entry
    ///
    /// Prompts for a new password and overwrites the existing
    /// encrypted entry.
    Update {
        /// Name of the entry to update
        name: String,
    },

    /// Change the master password
    ///
    /// Re-encrypts the entire vault using a new master password.
    /// A backup of the vault file is written before modification.
    Passwd,

    /// Generate a random password
    ///
    /// By default, generates a 16-character password using uppercase,
    /// lowercase, digits, and symbols.
    Gen {
        /// Length of the generated password
        #[arg(short, long, default_value_t = 16)]
        length: usize,

        /// Exclude uppercase characters (A–Z)
        #[arg(long)]
        no_uppercase: bool,

        /// Exclude lowercase characters (a–z)
        #[arg(long)]
        no_lowercase: bool,

        /// Exclude digits (0–9)
        #[arg(long)]
        no_digits: bool,

        /// Exclude symbols (e.g. !@#$%)
        #[arg(long)]
        no_symbols: bool,

        /// Exclude ambiguous characters like 'I', 'l', '1', 'O', '0'
        #[arg(long)]
        exclude_ambiguous: bool,

        /// Copy the generated password to the clipboard for 10 seconds
        #[arg(short, long)]
        copy: bool,
    },
}

#[derive(Args, Clone, Debug)]
pub struct AddArgs {
    /// Name of the entry (e.g. "github", "email", "bank")
    pub name: String,

    /// Overwrite an existing entry without prompting
    #[arg(short, long)]
    pub force: bool,
}
