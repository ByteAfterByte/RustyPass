use argon2::{Argon2, password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}};
use argon2::password_hash::rand_core::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::{Aead, KeyInit}};

pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], argon2::Error> {
    let mut key = [0u8; 32];

    Argon2::default().hash_password_into(master_password.as_bytes(), salt, &mut key)?;

    Ok(key)
}

pub fn hash_master_password(master_password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default().hash_password(master_password.as_bytes(), &salt).map_err(|e| format!("Failed to hash master password: {e}"))?.to_string();
   
    Ok(password_hash)
}

pub fn verify_master_password(master_password: &str, stored_hash: &str) -> Result<(), String> {
    let parsed_hash = PasswordHash::new(stored_hash).map_err(|e| format!("Invalid password hash: {e}"))?;
    Argon2::default().verify_password(master_password.as_bytes(), &parsed_hash).map_err(|_| "Incorrect master password.".to_string())
}

pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);

    let nonce = Nonce::from(nonce_bytes);

    let cipher_text = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|_| "Encryption failed.".to_string())?;

    let mut encrypted = nonce_bytes.to_vec();
    encrypted.extend(cipher_text);

    Ok(encrypted)
}

pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<String, String> {
    if encrypted.len() < 12 {
        return Err("Invalid encrytped data".to_string());
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);

    let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| "Invalid nonce".to_string())?;

    let nonce = Nonce::from(nonce_array);
    let cipher = ChaCha20Poly1305::new(key.into());

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| "Decryption failed".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "Decrypted data is not valid UTF-8".to_string())
}