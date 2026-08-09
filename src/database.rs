use crate::directory_handler;
use crate::encryption;

use rusqlite::{Connection, Result};

pub struct Entry {
    pub uuid: String,
    pub website: String,
    pub username: String,
    pub password: String,
}

pub struct DatabaseEncryptedEntry {
    pub uuid: String,
    pub website: Vec<u8>,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

pub fn connect_database() -> Result<Connection> {
    let database_path = directory_handler::get_directory().join("rustypass.db");
    Connection::open(database_path)
}

pub fn init_database(connection: &Connection) -> Result<()> {
    connection.execute("CREATE TABLE IF NOT EXISTS Vault (password_hash BLOB NOT NULL, encryption_salt BLOB NOT NULL)", [])?;
    connection.execute("CREATE TABLE IF NOT EXISTS Entries (uuid TEXT NOT NULL, website BLOB NOT NULL, username BLOB NOT NULL, password BLOB NOT NULL)", [])?;
    Ok(())
}

pub fn register_vault(
    connection: &Connection,
    password_hash: &str,
    encryption_salt: &[u8],
) -> Result<()> {
    connection.execute(
        "INSERT INTO Vault (password_hash, encryption_salt) VALUES (?, ?)",
        rusqlite::params![password_hash, encryption_salt],
    )?;
    Ok(())
}

pub fn get_vault_data(connection: &Connection) -> Result<(String, Vec<u8>), rusqlite::Error> {
    connection.query_row(
        "SELECT password_hash, encryption_salt FROM Vault LIMIT 1",
        [],
        |row| {
            let password_hash: String = row.get(0)?;
            let encryption_salt: Vec<u8> = row.get(1)?;

            Ok((password_hash, encryption_salt))
        },
    )
}

pub fn add_entry(connection: &Connection, entry: &Entry, key: &[u8; 32]) -> Result<(), String> {
    let encrypted_website = encryption::encrypt(key, &entry.website)?;
    let encrypted_username = encryption::encrypt(key, &entry.username)?;
    let encrypted_password = encryption::encrypt(key, &entry.password)?;

    connection
        .execute(
            "INSERT INTO Entries (uuid, website, username, password) VALUES (?1, ?2, ?3, ?4)",
            (
                &entry.uuid,
                encrypted_website,
                encrypted_username,
                encrypted_password,
            ),
        )
        .map_err(|e| format!("Failed to insert entry: {e}"))?;

    Ok(())
}

pub fn remove_entry(connection: &Connection, uuid: &str) -> Result<(), String> {
    connection
        .execute("DELETE FROM Entries WHERE uuid=?", [uuid])
        .map_err(|e| format!("Failed to delete entry: {e}"))?;
    Ok(())
}

pub fn get_entries(
    connection: &Connection,
) -> Result<Vec<DatabaseEncryptedEntry>, rusqlite::Error> {
    let mut statement =
        connection.prepare("SELECT uuid, website, username, password FROM Entries")?;

    let entries = statement
        .query_map([], |row| {
            Ok(DatabaseEncryptedEntry {
                uuid: row.get::<_, _>(0)?,
                website: row.get::<_, _>(1)?,
                username: row.get::<_, _>(2)?,
                password: row.get::<_, _>(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(entries)
}
