//! Provides utility functions for building transactions, converting data formats,
//! and interacting with raw blockchain data structures.
//!
//! This module contains essential helpers for:
//! - Deserializing raw UTXO data received from the ZkOS node.
//! - Monitoring addresses and selecting accounts for anonymity.
//! - Constructing specific `Input` and `Output` types (Coin, Memo, State) for transactions.
//! - Converting between hex strings, byte arrays, and cryptographic scalars.
use address::{Address, AddressType};

use curve25519_dalek::scalar::Scalar;
use quisquislib::elgamal::ElGamalCommitment;
use transaction::quisquislib::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

use zkvm::{zkos_types::OutputMemo, InputData, OutputData};
use zkvm::{
    zkos_types::{IOType, Input, Output, OutputCoin, Utxo},
    Commitment, String as ZkvmString,
};
lazy_static! {
    /// The URL of the ZkOS server, loaded from the `ZKOS_SERVER_URL` environment variable.
    ///
    /// # Panics
    /// Panics if the `ZKOS_SERVER_URL` environment variable is not set at runtime.
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_URL").expect("missing environment variable ZKOS_SERVER_URL");
}
use hex;
use serde::{Deserialize, Serialize};

/// A raw representation of a UTXO and its corresponding `Output`, as received from the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoOutputRaw {
    pub utxo_key: Vec<u8>,
    pub output: Vec<u8>,
    pub height: i64,
}
impl UtxoOutputRaw {
    /// Creates a new `UtxoOutputRaw`.
    pub fn new(utxo_key: Vec<u8>, output: Vec<u8>, height: i64) -> Self {
        Self {
            utxo_key,
            output,
            height,
        }
    }
    /// Deserializes and returns the `Output` from the raw byte vector.
    ///
    /// # Panics
    /// Panics if the `output` bytes cannot be deserialized into an `Output`.
    pub fn get_output(&self) -> Output {
        bincode::deserialize(&self.output).unwrap()
    }
    /// Returns the block height at which this UTXO was created.
    pub fn get_height(&self) -> i64 {
        self.height
    }
    /// Returns a clone of the raw UTXO key bytes.
    pub fn get_utxo_key(&self) -> Vec<u8> {
        self.utxo_key.clone()
    }
    /// Deserializes and returns the `Utxo` from the raw key bytes.
    ///
    /// # Panics
    /// Panics if the `utxo_key` bytes cannot be deserialized into a `Utxo`.
    pub fn get_utxo(&self) -> Utxo {
        bincode::deserialize(&self.utxo_key).unwrap()
    }
}

/// Scans a list of UTXOs and identifies which ones are owned by the provided secret key.
///
/// This function is useful for wallet applications to monitor the blockchain for
/// incoming funds or relevant transactions for a specific user.
///
/// # Note
/// The function name `coin_addrerss_monitoring` contains a typo and should be `coin_address_monitoring`.
///
/// # Parameters
/// - `vector_utxo_output_str`: A hex-encoded string representing a `Vec<UtxoOutputRaw>`.
/// - `sk`: The user's `RistrettoSecretKey` to check for ownership.
///
/// # Returns
/// A `Result` containing a vector of hex-encoded address strings owned by the secret key,
/// or an error message if decoding fails.
pub fn coin_addrerss_monitoring(
    vector_utxo_output_str: String,
    sk: RistrettoSecretKey,
) -> Result<Vec<String>, &'static str> {
    // recieves a vector of outputs as a hex string
    // recreate Vec<UtxoOutputRaw> from hex string
    // get vector bytes from hex
    let vector_utxo_bytes = match hex::decode(&vector_utxo_output_str) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Hex decode of UtxoOutputRaw vector failed"),
    };
    let vector_utxo_output_raw: Vec<UtxoOutputRaw> = match bincode::deserialize(&vector_utxo_bytes)
    {
        Ok(utxos) => utxos,
        Err(_) => return Err("Bincode decode of UtxoOutputRaw vector failed"),
    };

    // create vector of addresses
    let mut vector_addresses: Vec<String> = Vec::new();

    //Iterate over vector of UtxoOutputRawWasm to check if the output is owned by the secret key
    for utxo_output_raw in vector_utxo_output_raw {
        let output = utxo_output_raw.get_output();
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
    Ok(vector_addresses)
}

/// Selects a set of 7 random UTXOs from a provided list to serve as an anonymity set for a transaction.
///
/// The function ensures that the sender's own input is not included in the anonymity set.
/// It is designed for use in transactions like Quisquis transfers to obscure the true origin of funds.
///
/// # Parameters
/// - `vector_utxo_output_str`: A hex-encoded string representing a `Vec<UtxoOutputRaw>` from which to select.
/// - `sender_input`: The sender's own `Input`, which will be excluded from the selection.
///
/// # Returns
/// A vector containing 7 `Input`s to be used as the anonymity set.
///
/// # Panics
/// - Panics if the input string cannot be decoded from hex or deserialized.
/// - Panics if `vector_utxo_output_raw` contains fewer than 7 other accounts to select from.
pub fn select_anonymity_accounts(
    vector_utxo_output_str: String,
    sender_input: Input,
) -> Vec<Input> {
    // recreate Vec<UtxoOutputRaw> from hex string
    // get vector bytes from hex
    let vector_utxo_bytes = hex::decode(&vector_utxo_output_str).unwrap();
    let vector_utxo_output_raw: Vec<UtxoOutputRaw> =
        bincode::deserialize(&vector_utxo_bytes).unwrap();

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
        if inp != sender_input {
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
/// Creates an `OutputMemo` specifically for a trader's order.
///
/// The memo contains public commitments to the trader's initial margin, position size,
/// leverage, entry price, and order side.
///
/// # Parameters
/// - `script_address`: The hex-encoded address of the trading contract.
/// - `owner_address`: The hex-encoded address of the trader.
/// - `initial_margin`: The margin amount for the trade.
/// - `position_size`: The size of the position.
/// - `leverage`: The leverage used for the trade.
/// - `entry_price`: The target entry price for the order.
/// - `order_side`: The position type (`LONG` or `SHORT`).
/// - `scalar`: A random scalar for blinding the commitments.
/// - `timebounds`: The timebounds for the transaction's validity.
///
/// # Returns
/// An `Output` of type Memo containing the trader's order details.
pub fn create_output_memo_for_trader(
    script_address: String,                         // Hex address string
    owner_address: String,                          // Hex address string
    initial_margin: u64,                            // Initial Margin
    position_size: u64,                             // Position Size
    leverage: u64,                                  // Leverage
    entry_price: u64,                               // Entry Price
    order_side: crate::relayer_types::PositionType, // LONG / SHORT
    scalar: Scalar,                                 // Scalar for blinding
    timebounds: u32,                                // Timebounds
) -> Output {
    // create prover commitment on initial margin
    let commitment = Commitment::blinded_with_factor(initial_margin, scalar);
    // create Memo data for trader
    // Position Size, Leverage, Entry Price
    let leverage_commitment = Commitment::blinded_with_factor(leverage, scalar);
    let position = ZkvmString::from(Scalar::from(position_size));
    let price = ZkvmString::from(Scalar::from(entry_price));
    let side_scalar = order_side.to_scalar();
    let side = ZkvmString::from(side_scalar);
    let data: Vec<ZkvmString> = vec![
        position,
        ZkvmString::Commitment(Box::new(leverage_commitment)),
        price,
        side,
    ];
    // create OutputMemo
    let output_memo = OutputMemo::new(
        script_address,
        owner_address,
        commitment,
        Some(data),
        timebounds,
    );

    let output: Output = Output::memo(OutputData::memo(output_memo));
    output
}

/// Creates an `OutputMemo` for a lender's deposit.
///
/// The memo contains public commitments to the lender's deposit amount and their
/// resulting pool share.
///
/// # Parameters
/// - `script_address`: The hex-encoded address of the lending contract.
/// - `owner_address`: The hex-encoded address of the lender.
/// - `deposit`: The amount being deposited.
/// - `pool_share`: The normalized pool share received for the deposit.
/// - `scalar`: A random scalar for blinding the commitments.
/// - `timebounds`: The timebounds for the transaction's validity.
///
/// # Returns
/// An `Output` of type Memo containing the lender's deposit details.
pub fn create_output_memo_for_lender(
    script_address: String, // Hex address string
    owner_address: String,  // Hex address string
    deposit: u64,           // Deposit
    pool_share: u64,        // Noirmalized Pool Share
    scalar: Scalar,         // Scalar for blinding
    timebounds: u32,
) -> Output {
    // create prover commitment on deposit
    let commitment = Commitment::blinded_with_factor(deposit, scalar);
    // create Memo data for lender
    // Pool Share
    let pool_share_commitment = Commitment::blinded_with_factor(pool_share, scalar);
    let data: Vec<ZkvmString> = vec![ZkvmString::Commitment(Box::new(pool_share_commitment))];
    // create OutputMemo
    let output_memo = OutputMemo::new(
        script_address,
        owner_address,
        commitment,
        Some(data),
        timebounds,
    );

    let output: Output = Output::memo(OutputData::memo(output_memo));
    output
}

/// Creates a new `OutputCoin` for a private transfer.
///
/// This function generates an ElGamal-encrypted commitment to the amount, making it
/// observable only by the owner of the `owner_address`.
///
/// # Parameters
/// - `owner_address`: The hex-encoded address of the recipient.
/// - `amount`: The amount of the coin to be created.
/// - `scalar`: The random scalar (blinding factor) to be used for the ElGamal encryption.
///
/// # Returns
/// An `Option<Output>` containing the new coin `Output` on success, or `None` if the
/// address is invalid.
pub fn create_output_coin_for_trader(
    owner_address: String, // Hex address string
    amount: u64,           // Amount
    scalar: Scalar,        // rScalar used for blinding
) -> Option<Output> {
    // get public key from owner address
    let address = match Address::from_hex(&owner_address, AddressType::default()) {
        Ok(address) => address,
        Err(_) => return None,
    };
    let client_pk: RistrettoPublicKey = address.into();

    // create elgamal encryption on amount using scalar as blinding factor and the clients pk
    let client_encryption =
        ElGamalCommitment::generate_commitment(&client_pk, scalar, Scalar::from(amount));
    // create OutputCoin
    let output_coin: OutputCoin = OutputCoin::new(client_encryption, owner_address);

    Some(Output::from(output_coin))
}
/// Converts an `OutputCoin` into an `Input` for a new transaction.
///
/// # Parameters
/// - `out`: The `Output` (of type Coin) to be spent.
/// - `utxo`: The hex-encoded string of the `Utxo` corresponding to the `out`.
///
/// # Returns
/// A `Result` containing the new `Input` on success, or an error message on failure.
///
/// # Errors
/// Returns an error if the `utxo` string is not a valid hex-encoded `Utxo`, or if the
/// provided `out` is not an `OutputCoin`.
pub fn create_input_coin_from_output_coin(
    out: Output,
    utxo: String,
) -> Result<Input, &'static str> {
    let utxo_bytes = match hex::decode(&utxo) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid Utxo:: Hex Decode Error "),
    };
    let utxo: Utxo = match bincode::deserialize(&utxo_bytes) {
        Ok(utxo) => utxo,
        Err(_) => return Err("Invalid Utxo::Bincode Decode Error"),
    };

    let out_coin = match out.as_out_coin() {
        Some(coin) => coin,
        None => return Err("Invalid Output:: Not a Coin Output"),
    };
    let inp = Input::coin(InputData::coin(utxo, out_coin.clone(), 0));

    Ok(inp)
}
/// Converts an `OutputMemo` into an `Input` for a new transaction, specifying a withdrawal amount.
///
/// # Parameters
/// - `out`: The `Output` (of type Memo) to be spent.
/// - `utxo`: The hex-encoded string of the `Utxo` corresponding to the `out`.
/// - `withdraw_amount`: The amount to be withdrawn from the memo's value.
///
/// # Returns
/// A `Result` containing a tuple of the new `Input` and the blinding `Scalar` used,
/// or an error message on failure.
///
/// # Errors
/// Returns an error if the `utxo` string is invalid or if `out` is not an `OutputMemo`.
pub fn create_input_memo_from_output_memo(
    out: Output,
    utxo: String,
    withdraw_amount: u64,
) -> Result<(Input, Scalar), &'static str> {
    let utxo_bytes = match hex::decode(&utxo) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid Utxo:: Hex Decode Error "),
    };
    let utxo: Utxo = match bincode::deserialize(&utxo_bytes) {
        Ok(utxo) => utxo,
        Err(_) => return Err("Invalid Utxo::Bincode Decode Error"),
    };
    // get memo output from output
    let out_memo = match out.as_out_memo() {
        Some(memo) => memo,
        None => return Err("Invalid Output:: Not a Memo Output"),
    };
    let blinding = Scalar::random(&mut rand::thread_rng());
    let inp = Input::memo(InputData::memo(
        utxo,
        out_memo.clone(),
        0,
        Some(zkvm::Commitment::blinded_with_factor(
            withdraw_amount,
            blinding,
        )),
    ));

    Ok((inp, blinding))
}

/// Converts an `OutputState` into an `Input` for a new transaction.
///
/// # Parameters
/// - `out`: The `Output` (of type State) to be spent.
/// - `utxo`: The hex-encoded string of the `Utxo` corresponding to `out`.
/// - `script_data`: Optional data to be passed to the smart contract script.
///
/// # Returns
/// A `Result` containing the new `Input` on success, or an error message on failure.
///
/// # Errors
/// Returns an error if the `utxo` string is invalid or if `out` is not an `OutputState`.
pub fn create_input_state_from_output_state(
    out: Output,
    utxo: String,
    script_data: Option<Vec<ZkvmString>>,
) -> Result<Input, &'static str> {
    let utxo_bytes = match hex::decode(&utxo) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid Utxo:: Hex Decode Error "),
    };
    let utxo: Utxo = match bincode::deserialize(&utxo_bytes) {
        Ok(utxo) => utxo,
        Err(_) => return Err("Invalid Utxo::Bincode Decode Error"),
    };
    // get memo output from output
    let out_state = match out.as_out_state() {
        Some(state) => state,
        None => return Err("Invalid Output:: Not a State Output"),
    };

    let inp = Input::state(InputData::state(
        utxo,
        out_state.clone(),
        script_data,
        1, // witness is 1 for state for now
    ));

    Ok(inp)
}

/// Creates a new `OutputState` for a trade or lend order.
///
/// This function generates random blinding factors for the commitments.
///
/// # Parameters
/// - `nonce`: The new nonce for the state.
/// - `script_address`: The address of the contract.
/// - `owner_address`: The address of the state's owner.
/// - `tlv`: The total locked value.
/// - `tps`: The total pool share.
/// - `timebounds`: The transaction validity timebounds.
///
/// # Returns
/// A new `Output` of type State.
pub fn create_output_state_for_trade_lend_order(
    nonce: u32,
    script_address: String,
    owner_address: String,
    tlv: u64,
    tps: u64,
    timebounds: u32,
) -> Output {
    // create commitment for tlv using scalar
    let tlv_commitment = Commitment::blinded(tlv);
    let tps_commitment = Commitment::blinded(tps);
    // create state variables
    let state_variables: Vec<zkvm::String> = vec![zkvm::String::from(tps_commitment)];
    let output_state = zkvm::zkos_types::OutputState {
        nonce,
        script_address,
        owner: owner_address,
        commitment: tlv_commitment,
        state_variables: Some(state_variables),
        timebounds,
    };
    // create output
    Output::from(output_state)
}
/// Creates a new `OutputState` for a trade or lend order using client-provided scalars.
///
/// This provides more control over commitment creation compared to `create_output_state_for_trade_lend_order`.
///
/// # Parameters
/// - `nonce`: The new nonce for the state.
/// - `script_address`: The address of the contract.
/// - `owner_address`: The address of the state's owner.
/// - `tlv`: The total locked value.
/// - `tlv_blinding`: The scalar to use for blinding the TLV commitment.
/// - `tps`: The total pool share.
/// - `tps_blinding`: The scalar to use for blinding the TPS commitment.
/// - `timebounds`: The transaction validity timebounds.
///
/// # Returns
/// A new `Output` of type State.
pub fn create_output_state_for_trade_lend_order_with_scalar(
    nonce: u32,
    script_address: String,
    owner_address: String,
    tlv: u64,
    tlv_blinding: Scalar,
    tps: u64,
    tps_blinding: Scalar,
    timebounds: u32,
) -> Output {
    // create commitment for tlv using scalar
    let tlv_commitment = Commitment::blinded_with_factor(tlv, tlv_blinding);
    let tps_commitment = Commitment::blinded_with_factor(tps, tps_blinding);
    // create state variables
    let state_variables: Vec<zkvm::String> = vec![zkvm::String::from(tps_commitment)];
    let output_state = zkvm::zkos_types::OutputState {
        nonce,
        script_address,
        owner: owner_address,
        commitment: tlv_commitment,
        state_variables: Some(state_variables),
        timebounds,
    };
    // create output
    Output::from(output_state)
}
/// Converts a hex-encoded string to a `Scalar`.
///
/// # Returns
/// An `Option<Scalar>` containing the scalar on success, or `None` if the hex string
/// is invalid or does not represent 32 bytes of data.
pub fn hex_to_scalar(hex: String) -> Option<Scalar> {
    let byt = match hex::decode(&hex) {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    // Try to convert the vector into an array of 32 bytes
    let result: Result<[u8; 32], _> = byt.try_into();
    match result {
        Ok(bytes) => Some(Scalar::from_bytes_mod_order(bytes)),
        Err(_) => None,
    }
}

/// Extracts state information from a hex-encoded `Output`.
///
/// # Parameters
/// - `output_hex`: A hex-encoded string representing an `Output`.
///
/// # Returns
/// A `Result` containing a tuple of `(nonce, tlv, tlv_blinding, tps, tps_blinding)` on success.
///
/// # Errors
/// Returns an error if the hex string is invalid, if the `Output` is not a state output,
/// or if witness data is missing from the commitments.
pub fn get_state_info_from_output_hex(
    output_hex: String,
) -> Result<(u32, u64, Scalar, u64, Scalar), &'static str> {
    let output_bytes = match hex::decode(&output_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid Output:: Hex Decode Error "),
    };
    let output: Output = match bincode::deserialize(&output_bytes) {
        Ok(output) => output,
        Err(_) => return Err("Invalid Output::Bincode Decode Error"),
    };
    let out_state = match output.as_out_state() {
        Some(state) => state.clone(),
        None => return Err("Invalid Output:: Not a State Output"),
    };
    let nonce = out_state.nonce;

    let (tlv_witness, tlv_blinding) = match out_state.commitment.witness() {
        Some(witness) => witness,
        None => return Err("Invalid Commitment"),
    };

    let state_variables = match out_state.state_variables {
        Some(vars) => vars[0].clone(),
        None => return Err("Invalid Output:: State Variables not found"),
    };
    let tps_commitment = match state_variables.to_commitment() {
        Ok(commitment) => commitment,
        Err(_) => return Err("Invalid Commitment"),
    };
    let (tps_witness, tps_blinding) = match tps_commitment.witness() {
        Some(witness) => witness,
        None => return Err("Invalid Commitment"),
    };

    Ok((
        nonce,
        tlv_witness.to_integer().unwrap().to_u64().unwrap(),
        tlv_blinding,
        tps_witness.to_integer().unwrap().to_u64().unwrap(),
        tps_blinding,
    ))
}
/// Converts a JSON string representing a `Utxo` into a hex-encoded string.
///
/// # Panics
/// Panics if the JSON is invalid or serialization fails.
pub fn get_utxo_hex_from_json(utxo_json: String) -> String {
    let utxo: Utxo = serde_json::from_str(&utxo_json).unwrap();
    let utxo_bytes = bincode::serialize(&utxo).unwrap();
    let utxo_hex = hex::encode(&utxo_bytes);
    utxo_hex
}

/// Converts a `Scalar` to its hex-encoded string representation.
pub fn scalar_to_hex(scalar: Scalar) -> String {
    let byt = scalar.to_bytes();
    hex::encode(&byt)
}
