use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "rustypass")]
#[command(about = "A simple terminal based password manager.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // Initialized the password vault and sets up the master password.
    Init,
    
    // Generates a new password and saves it to the database.
    Generate {
        length: usize,
        website: String,
        username: String,
        
        #[arg(short = 'n', long)]
        numbers: bool,
        
        #[arg(short = 's', long)]
        symbols: bool,
    },

    // Deletes a password from its UUID.
    Delete {
        uuid: String,
    },

    // Lists all available entries.
    List,
}