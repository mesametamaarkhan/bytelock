//! CLI argument definitions for ByteLock.
//!
//! This module contains all `clap` structs and enums used to define the
//! command-line interface. No application logic should live here.

use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "bytelock")]
#[command(version = "0.1")]
#[command(about = "A simple Rust password manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init,
    Add(AddArgs),
    Get { name: String, #[arg(short, long)] copy: bool },
    List,
    Remove { name: String },
    Update { name: String },
    Passwd,
    Gen {
        #[arg(short, long, default_value_t = 16)]
        length: usize,
        #[arg(long)] no_uppercase: bool,
        #[arg(long)] no_lowercase: bool,
        #[arg(long)] no_digits: bool,
        #[arg(long)] no_symbols: bool,
        #[arg(long)] exclude_ambiguous: bool,
        #[arg(short, long)] copy: bool,
    },
}

#[derive(Args, Clone, Debug)]
pub struct AddArgs {
    pub name: String,
    #[arg(short, long)]
    pub force: bool,
}
