use address::{Address, AddressType};

use transaction::quisquislib::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

use zkvm::zkos_types::{IOType, Input, Output, OutputCoin, Utxo};
lazy_static! {
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_URL").expect("missing environment variable ZKOS_SERVER_URL");
}
use hex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoOutputRawWasm {
    pub utxo_key: Vec<u8>,
    pub output: Vec<u8>,
    pub height: i64,
}
impl UtxoOutputRawWasm {
    pub fn new(utxo_key: Vec<u8>, output: Vec<u8>, height: i64) -> Self {
        Self {
            utxo_key,
            output,
            height,
        }
    }
    pub fn get_output(&self) -> Output {
        bincode::deserialize(&self.output).unwrap()
    }
    pub fn get_height(&self) -> i64 {
        self.height
    }
    pub fn get_utxo_key(&self) -> Vec<u8> {
        self.utxo_key.clone()
    }
    pub fn get_utxo(&self) -> Utxo {
        bincode::deserialize(&self.utxo_key).unwrap()
    }
}

/// Function to create Utxo type from hex string
/// Returns Utxo as Json string.

pub fn create_utxo_from_hex_string(utxo_hex: String) -> Utxo {
    let utxo_bytes = hex::decode(&utxo_hex).unwrap();
    let utxo: Utxo = bincode::deserialize(&utxo_bytes).unwrap();

    //let j = serde_json::to_string(&utxo);
    //let msg_to_return = j.unwrap();
    //Ok(msg_to_return)
    utxo
}

/// Function to check list of coin utxos against the provided secretkey
/// Returns a list of all coin addresses that are owned by the secret key

pub fn coin_addrerss_monitoring(
    vector_utxo_output_str: String,
    sk: RistrettoSecretKey,
) -> Vec<String> {
    // recieves a vector of outputs as a hex string
    // recreate Vec<UtxoOutputRawWasm> from hex string
    // get vector bytes from hex
    let vector_utxo_bytes = hex::decode(&vector_utxo_output_str).unwrap();
    let vector_utxo_output_raw: Vec<UtxoOutputRawWasm> =
        bincode::deserialize(&vector_utxo_bytes).unwrap();

    // create secret key from seed
    //let sk: RistrettoSecretKey = hex_str_to_secret_key(&seed);

    // create vector of addresses
    let mut vector_addresses: Vec<String> = Vec::new();

    //Iterate over vector of UtxoOutputRawWasm to check if the output is owned by the secret key
    for utxo_output_raw in vector_utxo_output_raw {
        let output = utxo_output_raw.get_output();
        //let height = utxo_output_raw.get_height();
        match output.out_type {
            IOType::Coin => {
                // get owner address of the coin
                let address_hex = output.output.get_owner_address().unwrap();
                let address: Address =
                    Address::from_hex(&address_hex, AddressType::default()).unwrap();
                // get public key from address
                let pk: RistrettoPublicKey = address.into();
                if pk.verify_keypair(&sk).is_ok() {
                    vector_addresses.push(address.as_hex());
                }
            }
            _ => {}
        }
    }
    // convert vector of addresses to Json string
    // let j = serde_json::to_string(&vector_addresses);
    // let msg_to_return = j.unwrap();
    // Ok(msg_to_return)
    vector_addresses
}

/// Utility function to convert TxId into hex string
/// Returns TxId as hex string

pub fn tx_id_to_hex_string(utxo: String) -> String {
    let utxo: Utxo = serde_json::from_str(&utxo).unwrap();
    let tx_id_hex = utxo.tx_id_to_hex();
    tx_id_hex
}

/// Function to select anonymity accounts from the set of utxos provided
/// List of Inputs(derived from anonymity accounts) as json string  

pub fn select_anonymity_accounts(
    vector_utxo_output_str: String,
    sender_input: String,
) -> Vec<Input> {
    // recreate Vec<UtxoOutputRawWasm> from hex string
    // get vector bytes from hex
    let vector_utxo_bytes = hex::decode(&vector_utxo_output_str).unwrap();
    let vector_utxo_output_raw: Vec<UtxoOutputRawWasm> =
        bincode::deserialize(&vector_utxo_bytes).unwrap();

    // get the input from json string
    let input_sender: Input = serde_json::from_str(&sender_input).unwrap();

    // create vector of inputs
    let mut inputs_anonymity_vector: Vec<Input> = Vec::with_capacity(7);

    let num_utxos = vector_utxo_output_raw.len();
    // for random number generation
    let mut rng = rand::thread_rng();
    //Iterate over vector of UtxoOutputRawWasm to randomly select seven anonymity accounts
    // loop continues until seven anonymity accounts are selected
    let mut done = false;
    let mut counter = 0;
    while !done {
        let random_index: u32 = rand::Rng::gen_range(&mut rng, 0u32, num_utxos as u32);
        // get the utxo at the random index
        let raw_output = vector_utxo_output_raw[random_index as usize].clone();
        // convert the output into input
        let out = raw_output.get_output().as_out_coin().unwrap().to_owned();
        let utx = raw_output.get_utxo();
        let inp = OutputCoin::to_input(&out, utx, 0);

        // check if the input is not the sender input
        if inp != input_sender {
            // add the input to the vector of inputs
            inputs_anonymity_vector.push(inp);
            counter += 1;
        } else {
            println!("Sender input is selected");
        }
        // check if seven anonymity accounts are selected
        if counter == 7 {
            done = true;
        }
    }
    // convert vector of addresses to Json string
    // let j = serde_json::to_string(&inputs_anonymity_vector);
    // let msg_to_return = j.unwrap();
    // Ok(msg_to_return)
    inputs_anonymity_vector
}
