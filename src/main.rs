mod cli;
mod password_generator;
mod directory_handler;
mod database;
mod encryption;

use clap::Parser;
use cli::{Cli, Commands};
use rand;

use crate::database::Entry;

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let connection = database::connect_database().map_err(|e| format!("Unable to open connection: {e}"))?;

    database::init_database(&connection).map_err(|e| format!("Unable to initialize database: {e}"))?;

    let is_vault_empty: bool = connection.query_row("SELECT NOT EXISTS(SELECT 1 FROM Vault)", [], |row| row.get(0)).unwrap_or(true);
    let is_entries_empty: bool = connection.query_row("SELECT NOT EXISTS(SELECT 1 FROM Entries)", [], |row| row.get(0)).unwrap_or(true);


    match cli.command {
        Commands::Init => {
            if !is_vault_empty {
                return Err("A master password has already been chosen and the database already initialzed.".to_string());
            }

            let master_password = rpassword::prompt_password("Choose the master password: ").map_err(|e| format!("Failed to read password: {e}"))?;
    
            let confirmation = rpassword::prompt_password("Confirm the master password: ").map_err(|e| format!("Failed to read password: {e}"))?;
    
            if master_password != confirmation {
                return Err("Passwords do not match".to_string());
            }
        
            let password_hash = encryption::hash_master_password(&master_password)?;
        
            let encryption_salt: [u8; 32] = rand::random();
        
            database::register_vault(&connection, &password_hash, &encryption_salt).map_err(|e| format!("Failed to initialize vault: {e}"))?;
        
            println!("Master password successfully set! Make sure to remember it otherwise you'll lose all of your stored passwords forever.");
        }

        Commands::Generate { length, website, username, numbers, symbols } => {
            if is_vault_empty {
                return Err("You need to initialize first, the database and master password haven't been set up yet.".to_string());
            }

            let master_password = rpassword::prompt_password("Insert master password: ").map_err(|e| format!("Failed to read password: {e}"))?;

            let (password_hash, encryption_salt) = database::get_vault_data(&connection).map_err(|e| format!("Failed to read vault: {e}"))?;

            encryption::verify_master_password(&master_password, &password_hash,)?;

            let key = encryption::derive_key(&master_password, &encryption_salt).map_err(|e| format!("Failed to derive encryption key: {e}"))?;

            let password_data = password_generator::Password { use_numbers: numbers, use_symbols: symbols, length};

            let password = password_generator::generate_password(&password_data);

            println!("==========================================");
            println!("Password generated and saved to database.");
            println!("");
            println!("Website: {}", website);
            println!("Username/Email: {}", username);
            println!("Password: {}", password);
            println!("==========================================");

            let entry = Entry { uuid: uuid::Uuid::new_v4().to_string(), website, username, password };

            database::add_entry(&connection, &entry, &key)?;
        }

        Commands::Delete { uuid } => {
            if is_vault_empty {
                return Err("You need to initialize first, the database and master password haven't been set up yet.".to_string());
            }

            if is_entries_empty {
                return Err("No password has been registered yet.".to_string());
            }

            let master_password = rpassword::prompt_password("Insert master password: ").map_err(|e| format!("Failed to read password: {e}"))?;

            let (password_hash, encryption_salt) = database::get_vault_data(&connection).map_err(|e| format!("Failed to read vault: {e}"))?;

            encryption::verify_master_password(&master_password, &password_hash)?;

            let key = encryption::derive_key( &master_password, &encryption_salt, ) .map_err(|e| format!("Failed to derive encryption key: {e}"))?;

            let encrypted_website: Vec<u8> = connection.query_row("SELECT website FROM Entries WHERE uuid=?1", [&uuid], |row| row.get(0)).map_err(|e| format!("Failed to retrieve entry: {e}"))?;
            let website = encryption::decrypt(&key, &encrypted_website)?;
            
            database::remove_entry(&connection, &uuid).map_err(|e| format!("Unable to remove entry: {e}"))?;
            println!("Password for {} ({}) deleted succesfully.", website, uuid);
        }

        Commands::List => {
            if is_vault_empty {
                return Err("You need to initialize first, the database and master password haven't been set up yet.".to_string());
            }

            if is_entries_empty {
                return Err("No password has been registered yet.".to_string());
            }

            let master_password = rpassword::prompt_password("Insert master password: ").map_err(|e| format!("Failed to read password: {e}"))?;

            let (password_hash, encryption_salt) = database::get_vault_data(&connection).map_err(|e| format!("Failed to read vault: {e}"))?;

            encryption::verify_master_password(&master_password, &password_hash)?;

            let key = encryption::derive_key( &master_password, &encryption_salt, ) .map_err(|e| format!("Failed to derive encryption key: {e}"))?;

            let entries = database::get_entries(&connection) .map_err(|e| format!("Failed to retrieve entries: {e}"))?;
            
            for (uuid, website, username, password) in entries { 
                let website = encryption::decrypt(&key, &website)?;
                let username = encryption::decrypt(&key, &username)?;
                let password = encryption::decrypt(&key, &password)?;
                
                println!("UUID: {uuid}"); println!("Website: {website}");
                println!("Username: {username}");
                println!("Password: {password}");
                println!(); }
        }
    }

    Ok(())
}