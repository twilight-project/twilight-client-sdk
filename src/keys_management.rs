//! Handles the creation, loading, and management of encrypted wallet files.
//!
//! This module provides the core functionality for securely storing and retrieving
//! a user's master secret key on disk. It uses AES-128-CBC for encryption,
//! ensuring that private key material is always protected at rest. The main entry
//! point is the `init_wallet` function, which handles both creating new wallets
//! and loading existing ones.

use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use quisquislib::keys::PublicKey;
use quisquislib::keys::SecretKey;
use quisquislib::ristretto::RistrettoPublicKey;
use quisquislib::ristretto::RistrettoSecretKey;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

/// Encrypts data using AES-128-CBC.
///
/// # Panics
/// Panics if the key or IV lengths are not 16 bytes.
pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

/// Decrypts data using AES-128-CBC.
///
/// # Panics
/// Panics if the key or IV lengths are not 16 bytes, or if the
/// decryption fails due to incorrect padding or key.
pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_data).unwrap()
}

/// A utility function to write a byte slice to a specified file path.
///
/// # Errors
/// Returns an `io::Error` if the file cannot be created or written to.
pub fn write_bytes_to_file<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// A utility function to read the entire contents of a file into a byte vector.
///
/// # Errors
/// Returns an `io::Error` if the file cannot be opened or read.
pub fn read_bytes_from_file<P: AsRef<Path>>(file_path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Creates a new secret key from a seed, encrypts it, and saves it to a file.
///
/// # Panics
/// Panics if it fails to write the encrypted key to the specified `file_path`.
pub fn new_wallet(password: &[u8], file_path: String, iv: &[u8], seed: &str) -> RistrettoSecretKey {
    let secret_key = hex_str_to_secret_key(seed);
    let private_key_bytes = secret_key.as_bytes();
    let encrypted_private_key = encrypt(&private_key_bytes, password, iv);
    let result = write_bytes_to_file(file_path, encrypted_private_key.as_slice());
    match result {
        Ok(_) => (),
        Err(e) => {
            panic!(
                "Can not write secret key bytes to the file: {}",
                e.to_string()
            )
        }
    }
    secret_key
}

/// Loads an existing encrypted wallet file and decrypts it.
///
/// Returns `None` if the file cannot be read.
///
/// # Panics
/// Panics if decryption fails, which typically means the password or IV is incorrect.
pub fn load_wallet(password: &[u8], file_path: String, iv: &[u8]) -> Option<RistrettoSecretKey> {
    let encypted_private_key_bytes = read_bytes_from_file(file_path);
    let encypted_private_key_bytes = match encypted_private_key_bytes {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    let private_key_bytes = decrypt(encypted_private_key_bytes.as_slice(), password, iv);
    let secret_key = quisquislib::ristretto::RistrettoSecretKey::from_bytes(&private_key_bytes);
    Some(secret_key)
}

/// Initializes a new encrypted wallet or loads an existing one.
///
/// This is the primary function for wallet setup. If a file exists at `file_path`,
/// it attempts to load and decrypt it. If not, it creates a new wallet using the
/// provided seed.
///
/// # Parameters
/// - `password`: A 16-byte key for AES-128 encryption/decryption.
/// - `file_path`: The path to the wallet file.
/// - `iv`: A 16-byte initialization vector for AES-128-CBC.
/// - `key_seed`: A seed string used to generate the private key. Required if the wallet file does not exist.
///
/// # Returns
/// Returns `Some(RistrettoSecretKey)` on success.
/// Returns `None` if the file does not exist and `key_seed` is also `None`.
///
/// # Example
/// ```rust,no_run
/// use twilight_client_sdk::keys_management;
///
/// let password = b"a_16_byte_key!!";
/// let iv = b"a_16_byte_iv!!!!";
/// let seed = "a_secure_seed_string";
///
/// let secret_key = keys_management::init_wallet(
///     password,
///     "wallet.bin".to_string(),
///     iv,
///     Some(seed.to_string()),
/// ).expect("Failed to init wallet");
/// ```
pub fn init_wallet(
    password: &[u8],
    file_path: String,
    iv: &[u8],
    key_seed: Option<String>,
) -> Option<RistrettoSecretKey> {
    if Path::new(&file_path).exists() {
        load_wallet(password, file_path, iv)
    } else {
        let seed = match key_seed {
            Some(seed) => seed,
            None => return None,
        };
        Some(new_wallet(password, file_path, iv, &seed))
    }
}

/// Derives and returns a public key from a secret key.
///
/// For efficiency, this function caches the public key on disk. It first attempts
/// to read the key from `file_path`. If the file doesn't exist, it derives the key,
/// saves it to the path, and then returns it.
///
/// # Panics
/// Panics if it fails to read or write the public key file.
pub fn get_public_key(secret_key: RistrettoSecretKey, file_path: String) -> RistrettoPublicKey {
    if Path::new(&file_path).exists() {
        let public_key_bytes = read_bytes_from_file(file_path).unwrap();
        RistrettoPublicKey::from_bytes(&public_key_bytes).unwrap()
    } else {
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key, &mut OsRng);
        let result = write_bytes_to_file(file_path, &public_key.as_bytes());
        match result {
            Ok(_) => (),
            Err(e) => {
                panic!(
                    "Can not write public key bytes to the file: {}",
                    e.to_string()
                )
            }
        }
        public_key
    }
}

/// A utility function to create a `RistrettoSecretKey` from a string seed.
///
/// Note: This function directly uses the bytes of the string as the seed.
/// For enhanced security, a key derivation function like Blake2b or SHA256
/// should be used to hash the input seed into a fixed-size key.
// TODO: Use a proper KDF to derive the secret key from the seed string.
pub fn hex_str_to_secret_key(seed: &str) -> RistrettoSecretKey {
    //derive private key from the raw bytes of the seed string.
    SecretKey::from_bytes(seed.as_bytes())
}

#[cfg(test)]
mod test {
    use super::init_wallet;
    use dotenvy::dotenv;
    #[test]
    pub fn get_key_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let password = b"your_password_he";
        let iv = b"your_password_he"; // Use a secure way to handle the password
                                      // load seed from env
        let seed = std::env::var("TEST_SEED").unwrap_or_else(|_| "some_random_seed".to_string());

        let wallet = init_wallet(
            password,
            "wallet.txt".to_string(),
            iv,
            Some(seed.to_string()),
        );
        println!("wallet {:?}", wallet);
    }
}
