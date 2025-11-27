use clap::{Parser, Subcommand};

//Bytelock - A simple password manager (WIP)
#[derive(Parser)]
#[command(name = "bytelock")]
#[command(version = "0.1")]
#[command(about = "A simple Rust password manager", long_about = None)]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	/// Create new encrypted vault
	Init,
	
	/// Add a new password entry
	Add {
		name: String,
	},

	/// Get a stored password
	Get {
		name: String,
	},
	
	/// List all stored entries (names only)
	List,
}

fn main() {
	let cli = Cli::parse();
	
	match cli.command {
		Commands::Init => {
			println!("Initializing new vault...");
		}
		Commands::Add { name } => {
			println!("Adding new entry: {}", name);
		}
		Commands::Get { name } => {
			println!("Fetching entry: {}", name);
		}
		Commands::List => {
			println!("Listing all entries...");
		}
	}
}
