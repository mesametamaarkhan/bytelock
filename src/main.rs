//! ByteLock — A minimal, local, encrypted password manager.
//!
//! This file is the application entry point. It is intentionally kept small
//! and is responsible only for:
//!
//! - Parsing CLI arguments
//! - Dispatching subcommands
//! - Exiting with appropriate status codes
//!
//! All command implementations live in `commands/` and all user interaction
//! helpers live in `ui.rs`.

use clap::Parser;

mod cli;
mod commands;
mod crypto;
mod vault;
mod ui;
mod auth;

fn main() {
    let cli = cli::Cli::parse();
    commands::dispatch(cli);
}
