use argon2::password_hash::rand_core::OsRng;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};

// Generates the key from the master password and the salt.
// The salt is generated once when you init the database.
pub fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32], argon2::Error> {
    let mut key = [0u8; 32];

    Argon2::default().hash_password_into(master_password.as_bytes(), salt, &mut key)?;

    Ok(key)
}

// Generates the salt and uses it to hash the master password.
pub fn hash_master_password(master_password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash master password: {e}"))?
        .to_string();

    Ok(password_hash)
}

// Checks if the hash of the inputed password matches the hash inside the database.
// If it matches, the password is correct.
pub fn verify_master_password(master_password: &str, stored_hash: &str) -> Result<(), String> {
    // This parses the stored hash, turns it into a PasswordHash object so that Argon2 can read it.
    let parsed_hash =
        PasswordHash::new(stored_hash).map_err(|e| format!("Invalid password hash: {e}"))?;

    Argon2::default()
        .verify_password(master_password.as_bytes(), &parsed_hash)
        .map_err(|_| "Incorrect master password.".to_string())
}

// Encrypts data using the key.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, String> {
    // Initializes the cipher algorithm using the key.
    let cipher = ChaCha20Poly1305::new(key.into());

    // The nonce is an array of random bytes used to make sure each encryption is different even if the content is the same.
    // You can consider this as noise we add to make decryption harder.
    // It starts as an empty array of 0s and we then fill them with random.
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);

    let nonce = Nonce::from(nonce_bytes);

    // We add the nonce to the encryption.
    // Notice encrypt(nonce, text) doesn't add the nonce to the encryption, it just uses it as "seed".
    let cipher_text = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "Encryption failed.".to_string())?;

    // We add the nonce to the encrypted "string" itself.
    let mut encrypted = nonce_bytes.to_vec();
    encrypted.extend(cipher_text);

    Ok(encrypted)
}

pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<String, String> {
    // Since the Nonce is exactly 12 bytes, if the encrypted string is less than 12, the data is invalid.
    if encrypted.len() < 12 {
        return Err("Invalid encrytped data".to_string());
    }

    // We extract the first 12 bytes of the encrypted text, aka the Nonce.
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);

    // Notices try_into() turns the array from a byte slice to a fixed-size array of 12.
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| "Invalid nonce".to_string())?;

    let nonce = Nonce::from(nonce_array);
    let cipher = ChaCha20Poly1305::new(key.into());

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "Decryption failed".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "Decrypted data is not valid UTF-8".to_string())
}
