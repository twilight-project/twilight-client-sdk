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

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_data).unwrap()
}

pub fn write_bytes_to_file<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(bytes)?;
    Ok(())
}

pub fn read_bytes_from_file<P: AsRef<Path>>(file_path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub fn new_wallet(password: &[u8], file_path: String, iv: &[u8], seed: &str) -> RistrettoSecretKey {
    let secret_key = hex_str_to_secret_key(seed);
    let private_key_bytes = secret_key.as_bytes();
    let encrypted_private_key = encrypt(&private_key_bytes, password, iv);
    let result = write_bytes_to_file(file_path, encrypted_private_key.as_slice());
    match result {
        Ok(_) => (),
        Err(_) => {
            panic!("Can not write secret key bytes to the file")
        }
    }
    return secret_key;
}

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

pub fn get_public_key(secret_key: RistrettoSecretKey, file_path: String) -> RistrettoPublicKey {
    if Path::new(&file_path).exists() {
        let public_key_bytes = read_bytes_from_file(file_path.to_string()).unwrap();
        let public_key = RistrettoPublicKey::from_bytes(&public_key_bytes.as_slice()).unwrap();
        return public_key;
    } else {
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key, &mut OsRng);
        let result = write_bytes_to_file(file_path.to_string(), &public_key.as_bytes());
        match result {
            Ok(_) => (),
            Err(_) => {
                panic!("Can not write public key bytes to the file")
            }
        }
        return public_key;
    }
}

// }

pub fn main() {
    // Example usage - in production, use secure password management and random seed generation
    println!(
        "Warning: This is example code only. Never use hardcoded passwords or seeds in production!"
    );

    // Example of how to use the wallet functions:
    // 1. Generate a secure password and IV
    // 2. Generate or input a secure seed
    // 3. Initialize wallet with proper error handling

    // let password = // Get from secure input
    // let iv = // Generate random IV
    // let seed = // Generate or input secure seed
    // let wallet = init_wallet(password, "wallet.txt".to_string(), iv, Some(seed));
}

/// Utility function used for converting seed to Ristretto secret Key
/// TODO: Update the function to reflect Hash of seed to increase security
pub fn hex_str_to_secret_key(seed: &str) -> RistrettoSecretKey {
    // Future enhancement: Add proper hashing for security and restrict size to 32 bytes
    // Example: Use SHA-256 or similar cryptographic hash function

    // Derive private key (currently using direct conversion)
    SecretKey::from_bytes(seed.as_bytes())
}

#[cfg(test)]
mod test {
    use super::init_wallet;
    #[test]
    pub fn get_key_test() {
        // Generate test credentials for testing purposes only
        let password = b"test_password_16"; // 16 bytes for AES128
        let iv = b"test_iv_16_bytes"; // 16 bytes IV

        // Get test seed from environment variable or use fallback
        let test_seed = std::env::var("TEST_SEED").unwrap_or_else(|_| {
            "test_seed_for_unit_testing_only_do_not_use_in_production_environment".to_string()
        });

        let wallet = init_wallet(
            password,
            "test_wallet.txt".to_string(),
            iv,
            Some(test_seed.to_string()),
        );
        println!("wallet {:?}", wallet);

        // Clean up test file
        std::fs::remove_file("test_wallet.txt").ok();
    }
}
