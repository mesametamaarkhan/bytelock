//! ByteLock — A minimal, local, encrypted password manager.
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
