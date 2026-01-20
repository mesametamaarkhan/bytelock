//! Command dispatch layer for ByteLock.
//!
//! This module maps parsed CLI commands to their concrete implementations.
//! Each command lives in its own file and exposes a single `run()` function.

use crate::cli::{Cli, Commands};

pub mod init;
pub mod add;
pub mod get;
pub mod list;
pub mod remove;
pub mod update;
pub mod passwd;
pub mod gen_pw;

pub fn dispatch(cli: Cli) {
    match cli.command {
        Commands::Init => init::run(),
        Commands::Add(args) => add::run(args),
        Commands::Get { name, copy } => get::run(name, copy),
        Commands::List => list::run(),
        Commands::Remove { name } => remove::run(name),
        Commands::Update { name } => update::run(name),
        Commands::Passwd => passwd::run(),
        Commands::Gen {
            length,
            no_uppercase,
            no_lowercase,
            no_digits,
            no_symbols,
            exclude_ambiguous,
            copy,
        } => gen_pw::run(
            length,
            !no_uppercase,
            !no_lowercase,
            !no_digits,
            !no_symbols,
            exclude_ambiguous,
            copy,
        ),
    }
}
