use rand::RngExt;
use std::char;

pub struct Password {
    pub use_numbers: bool,
    pub use_symbols: bool,
    pub length: usize,
}

const LETTERS: &str = "abcdefghijklmnoqprstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "1234567890";
const SYMBOLS: &str = "!@#$%^&*(){}[]_-=+?";

pub fn generate_password(password_data: &Password) -> String {
    let mut characters = String::from(LETTERS);
    let mut password = String::with_capacity(password_data.length);

    let mut random = rand::rng();

    if password_data.use_numbers {
        characters.push_str(NUMBERS);
    }

    if password_data.use_symbols {
        characters.push_str(SYMBOLS);
    }

    let bytes = characters.as_bytes();

    for _ in 0..password_data.length {
        let index = random.random_range(0..bytes.len());
        password.push(bytes[index] as char);
    }

    password
}
