use aes::Aes128;
use quisquislib::keys::PublicKey;
use quisquislib::keys::SecretKey;
use quisquislib::ristretto::RistrettoSecretKey;
use quisquislib::ristretto::RistrettoPublicKey;
use serde::{Serialize, Deserialize};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{thread_rng, Rng};
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;
use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::path::Path;
use hex;

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

fn new_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey{
    let secret_key: quisquislib::ristretto::RistrettoSecretKey = quisquislib::keys::SecretKey::random(&mut OsRng);
    let private_key_bytes = secret_key.as_bytes();
    let encrypted_private_key = encrypt(&private_key_bytes, password, iv);
    write_bytes_to_file(file_path, encrypted_private_key.as_slice());
    return secret_key;
}

fn load_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey {
    let encypted_private_key_bytes = read_bytes_from_file(file_path).unwrap();
    let private_key_bytes = decrypt(encypted_private_key_bytes.as_slice(), password, iv);
    let secret_key = quisquislib::ristretto::RistrettoSecretKey::from_bytes(&private_key_bytes);
    return secret_key
}

fn init_wallet(password: &[u8], file_path: String, iv: &[u8]) -> RistrettoSecretKey{
    let wallet : RistrettoSecretKey;
    if Path::new(&file_path).exists(){
        wallet = load_wallet(password, file_path, iv);
    }else{
        wallet = new_wallet(password, file_path, iv);
    }
    return wallet
}

fn get_public_key(secret_key: RistrettoSecretKey) -> RistrettoPublicKey{
    let file_path = "public_key.txt";
    if Path::new(file_path).exists(){
        let public_key_bytes = read_bytes_from_file(file_path.to_string()).unwrap();
        let public_key = RistrettoPublicKey::from_bytes(&public_key_bytes.as_slice()).unwrap();
        return public_key
    }else{
        let public_key = RistrettoPublicKey::from_secret_key(&secret_key, &mut OsRng);
        write_bytes_to_file(file_path.to_string(), &public_key.as_bytes());
        return public_key
    }

}




// }

fn main() {
    let password = b"your_password_here";
    let iv = b"your_password_here"; // Use a secure way to handle the password
    
    let wallet = init_wallet(password, "wallet.txt".to_string(), iv );
    // let loaded_wallet = Wallet::load_from_file("wallet.json".to_string());
}
