use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex;
use quisquislib::keys::PublicKey;
use quisquislib::keys::SecretKey;
use quisquislib::ristretto::RistrettoPublicKey;
use quisquislib::ristretto::RistrettoSecretKey;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(encrypted_data).unwrap()
}

fn write_bytes_to_file<P: AsRef<Path>>(file_path: P, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn read_bytes_from_file<P: AsRef<Path>>(file_path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn new_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey {
    let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    // let secret_key: quisquislib::ristretto::RistrettoSecretKey =
    //   quisquislib::keys::SecretKey::random(&mut OsRng);
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

fn load_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey {
    let encypted_private_key_bytes = read_bytes_from_file(file_path).unwrap();
    let private_key_bytes = decrypt(encypted_private_key_bytes.as_slice(), password, iv);
    let secret_key = quisquislib::ristretto::RistrettoSecretKey::from_bytes(&private_key_bytes);
    return secret_key;
}

fn init_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey {
    let wallet: RistrettoSecretKey;
    if Path::new(&file_path).exists() {
        wallet = load_wallet(password, file_path, iv);
    } else {
        wallet = new_wallet(password, file_path, iv);
    }
    return wallet;
}

fn get_public_key(secret_key: RistrettoSecretKey) -> RistrettoPublicKey {
    let file_path = "public_key.txt";
    if Path::new(file_path).exists() {
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

fn main() {
    let password = b"your_password_here";
    let iv = b"your_password_here"; // Use a secure way to handle the password

    let wallet = init_wallet(password, "wallet.txt".to_string(), iv);
    // let loaded_wallet = Wallet::load_from_file("wallet.json".to_string());
}

//Utility function used for converting seed to Ristretto secret Key
//UPDATE the function to reflect Hash of seed to increase security
//************************ */
fn hex_str_to_secret_key(seed: &str) -> RistrettoSecretKey {
    //doing hash for more security and restricting size to 32 bytes
    //let mut hasher = Keccak256::new();
    //hasher.update(seed);
    //let hash_32: [u8; 32] = hasher.finalize().try_into().unwrap();

    //derive private key
    SecretKey::from_bytes(seed.as_bytes())
}

#[cfg(test)]
mod test {
    use super::init_wallet;
    #[test]
    fn get_key_test() {
        let password = b"your_password_he";
        let iv = b"your_password_he"; // Use a secure way to handle the password

        let wallet = init_wallet(password, "wallet.txt".to_string(), iv);
        println!("wallet {:?}", wallet);
    }
}
