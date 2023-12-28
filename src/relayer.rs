use crate::relayer_rpcclient::method::*;
use crate::{
    relayer_types::{CreateLendOrder, CreateLendOrderZkos, ZkosCreateOrder},
    *,
};
use address::{Address, AddressType, Script};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use quisquislib::{
    accounts::Account,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use relayer_types::{
    CancelTraderOrder, CancelTraderOrderZkos, CreateTraderOrder, CreateTraderOrderZkos,
    ExecuteLendOrder, ExecuteLendOrderZkos, ExecuteTraderOrder, ExecuteTraderOrderZkos,
    QueryLendOrder, QueryLendOrderZkos, QueryTraderOrder, QueryTraderOrderZkos, TXType,
    ZkosCancelMsg, ZkosQueryMsg, ZkosSettleMsg,
};
// use zkvm::types::String as ZkvmString;
use std::convert::From;
use uuid::Uuid;
use zkschnorr::Signature;
use zkvm::{
    zkos_types::{OutputMemo, ValueWitness},
    IOType, Input, InputData, Output, OutputData, Utxo,
};

/// Get hardcodded script address.
/// as hex string
/// Returing default value for now but will be changed to actual script address LATER

pub fn get_harcoded_script_address() -> String {
    let script_address = Script::default();
    //create Address
    let address = script_address.as_hex();

    //let j = serde_json::to_string(&address);
    //let msg_to_return = j.unwrap();
    address
}

/// create Output for Memo
///     
pub fn create_output_for_memo(
    script_address: String, // Hex address string
    owner_address: String,  // Hex address string
    balance: u64,
    order_size: u64,
    scalar: String, // Hex string of Scalar
) -> Output {
    // recreate scalar bytes from hex string
    let scalar_bytes = hex::decode(&scalar).unwrap();
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes.try_into().unwrap());

    let output_memo =
        OutputMemo::new_from_wasm(script_address, owner_address, balance, order_size, scalar);

    let output: Output = Output::memo(OutputData::memo(output_memo));
    //let j: Result<String, serde_json::Error> = serde_json::to_string(&output);
    //let msg_to_return = j.unwrap();
    output
}

/// create input from output
/// Works for memo and Coin type of Inputs only

pub fn create_input_from_output(
    out: Output,
    utxo: String,
    withdraw_amount: u64, //ONLY NEEDED FOR MEMO in case of settlement transactions
) -> Result<Input, &'static str> {
    //let out: Output = serde_json::from_str(&output).unwrap();
    //let utxo: Utxo = serde_json::from_str(&utxo).unwrap();
    let utxo: Utxo = bincode::deserialize(&hex::decode(utxo).unwrap()).unwrap();
    let mut inp: Input;
    match out.out_type {
        IOType::Coin => {
            let out_coin = out.output.get_output_coin().unwrap().to_owned();
            inp = Input::coin(InputData::coin(utxo, out_coin.clone(), 0));
        }
        IOType::Memo => {
            let out_memo = out.output.get_output_memo().unwrap().to_owned();
            inp = Input::memo(InputData::memo(
                utxo,
                out_memo.clone(),
                0,
                Some(zkvm::Commitment::blinded(withdraw_amount)), /*SHOULD BE HANDLES DISCREETly LATER. The sign happens on this amount while the user is unaware of the settlement amount figure at the time of creation of this memo */
            ));
        }
        //Also what happens at the time of Liquadation. The tx needs input from user which he may not be willing to give
        _ => return Err("Invalid IOType"),
    }
    // let j = serde_json::to_string(&inp);
    // let msg_to_return = j.unwrap();
    Ok(inp)
}

///Sign a msg using private key and public key
/// Returns signature as string
/// msg is the cancel message request
pub fn sign_message_by_pk(msg: String, pk: String, secret_key: &RistrettoSecretKey) -> Signature {
    //let msg: String = serde_json::from_str(&msg).unwrap();
    let pk: RistrettoPublicKey = serde_json::from_str(&pk).unwrap();

    let message = bincode::serialize(&msg).unwrap();

    let signature: Signature = pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    // let sig = sign(&msg.as_bytes(), &pk, &sk);
    //let j = serde_json::to_string(&signature);
    //let msg_to_return = j.unwrap();
    //Ok(msg_to_return)
    signature
}

///Sign an Input Coin/Memo using private key and public key
/// Returns signature as string
///
//#[wasm_bindgen(js_name = signInput)]
pub fn sign_input(
    input: Input,
    pub_key: RistrettoPublicKey,
    secret_key: &RistrettoSecretKey,
) -> Signature {
    let mut message: Vec<u8> = Vec::new();

    // if input.in_type == IOType::Coin {
    //     // Just sign the input directly with Witness set to 0
    //     let input_sign = input.as_input_for_signing();
    //     message = bincode::serialize(&input_sign).unwrap();
    // } else if input.in_type == IOType::Memo {
    //     // Create the Verifier View of the Memo and set the Witness to 0
    //     let memo = input.as_out_memo().unwrap().to_owned();
    //     //convert commitment into point
    //     let memo_verifier = memo.verifier_view();

    //     // create signer view
    //     let input_sign = Input::memo(InputData::memo(
    //         input.as_utxo().unwrap().to_owned(),
    //         memo_verifier,
    //         0,
    //         Some(input.input.get_coin_value_from_memo().unwrap().to_owned()),
    //     ));
    //     message = bincode::serialize(&input_sign).unwrap();
    // }
    // let
    let signature: Signature =
        pub_key.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());
    signature
}

// Returns ValueWitness (Signature, SigmaProof) as string
/// Input is Coin/Memo
///

///Create a ZkosCreateTraderOrder OR ZkosCreateLendOrder from ZkosAccount
/// Returns ZkosCreateOrder as string
/// input : Input::coin(InputData::coin(utxo, out_coin.clone(), 0));
/// output : Output::memo(OutputData::memo(_memo));
/// seed : Secret key
/// rscalar: Scalar used to create Encryption and Commitment
/// value: value of the order.  Should be equal to the balance of the input otherwise the difference might be burned
//#[wasm_bindgen(js_name = createZkOSOrder)]
///Utility function used to create ZkosCreateOrder type
pub fn create_zkos_order(
    input: Input,
    output: Output,
    secret_key: RistrettoSecretKey,
    rscalar: Scalar,
    value: u64,
) -> ZkosCreateOrder {
    //get Pk from input owner address and create account
    let addr_str = input.input.owner().unwrap();
    let address: Address = Address::from_hex(&addr_str, AddressType::Standard).unwrap();
    let pubkey = address.as_coin_address().public_key;

    let commitment: zkvm::Commitment = output.as_out_memo().unwrap().commitment.clone();
    let pedersen_commitment: CompressedRistretto = commitment.into();

    //get Pk from input owner address and create account
    let enc_acc: Account =
        Account::set_account(pubkey.clone(), input.as_encryption().unwrap().clone());

    //create the Verifier View of the Coin and set the Witness to 0
    let input_sign = input.as_input_for_signing();
    // create InputCoin Witness
    let witness = ValueWitness::create_value_witness(
        input_sign.clone(),
        secret_key,
        output.clone(),
        enc_acc,
        pubkey.clone(),
        pedersen_commitment.clone(),
        value,
        rscalar,
    );
    //let witness: ValueWitness = set_value_witness(input, secret_key, enc_acc, pubkey, pedersen_commitment, value, rscalar);
    ZkosCreateOrder::new(input, output, witness)
}

///Create a ZkosCreateTraderOrder from ZkosAccount
///
pub fn create_trader_order_zkos(
    input_coin: String,
    output_memo: String,
    secret_key: RistrettoSecretKey,
    rscalar: String, // Hex string of Scalar
    value: u64,
    account_id: String,
    position_type: String,
    order_type: String,
    leverage: f64,
    initial_margin: f64,
    available_margin: f64,
    order_status: String,
    entryprice: f64,
    execution_price: f64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //prepare data for signature and same value proof
    let input: Input = serde_json::from_str(&input_coin).unwrap();
    let output: Output = serde_json::from_str(&output_memo).unwrap();
    //let scalar_hex: String = serde_json::from_str(&rscalar).unwrap();
    let scalar_bytes = hex::decode(&rscalar).unwrap();
    let rscalar = Scalar::from_bytes_mod_order(scalar_bytes.try_into().unwrap());

    let zkos_order = create_zkos_order(input, output, secret_key, rscalar, value);
    let create_order: CreateTraderOrder = CreateTraderOrder::new(
        account_id,
        position_type,
        order_type,
        leverage,
        initial_margin,
        available_margin,
        order_status,
        entryprice,
        execution_price,
    );
    let create_zkos_order_full: CreateTraderOrderZkos =
        CreateTraderOrderZkos::new(create_order, zkos_order);
    let order_result = create_zkos_order_full.submit_order();
    // let order_hex: String = create_zkos_order_full.encode_as_hex_string();
    //println!("order_hex: {}", order_hex);
    //let j = serde_json::to_string(&order_hex);
    //let msg_to_return = j.unwrap();
    //Ok(msg_to_return)
    // order_hex
    order_result
}

/// ExecuteOrderZkos. Used to settle trade or lend orders
/// Input = Memo
/// seed  = private signature to derive secret key
/// rest of the normal settle order message
/// tx_type = "ORDERTX" for settling trader orders
/// tx_type = "LENDTX" for settling lend orders
/// returns hex string of the object
pub fn execute_order_zkos(
    input_memo: String,
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: String,
    order_type: String,
    settle_margin_settle_withdraw: f64,
    order_status: String,
    execution_price_poolshare_price: f64,
    tx_type: String,
) -> String {
    //prepare data for signature and same value proof
    //recreate uuid
    let uuid: Uuid = serde_json::from_str(&uuid).unwrap();
    // let u_bytes = hex::decode(uuid_hex).unwrap();
    //let uuid: Uuid = Uuid::from_bytes(u_bytes.try_into().unwrap());

    let input: Input = serde_json::from_str(&input_memo).unwrap();
    //extract publickey from owner address of input memo
    let owner: String = input.as_owner_address().unwrap().to_owned();
    let pk: RistrettoPublicKey = Address::from_hex(&owner, AddressType::default())
        .unwrap()
        .as_coin_address()
        .public_key;

    let signature: Signature = sign_input(input.clone(), pk.clone(), secret_key);

    //Let order type (Trade or Lend)
    let tx_type: relayer::TXType = relayer::TXType::from_str(&tx_type).unwrap();
    let settle_zkos_msg: ZkosSettleMsg = ZkosSettleMsg::new(input.clone(), signature.clone());
    let mut settle_hex: String = String::new();
    match tx_type {
        TXType::ORDERTX => {
            let execute_order: ExecuteTraderOrder = ExecuteTraderOrder::new(
                account_id,
                uuid,
                order_type,
                settle_margin_settle_withdraw,
                order_status,
                execution_price_poolshare_price,
            );
            //let settle_zkos_msg: ZkosSettleMsg = ZkosSettleMsg::new(input.clone(), signature.clone());
            let order_zkos_settle: ExecuteTraderOrderZkos =
                ExecuteTraderOrderZkos::new(execute_order, settle_zkos_msg.clone());
            settle_hex = order_zkos_settle.encode_as_hex_string();
        }
        TXType::LENDTX => {
            let execute_lend: ExecuteLendOrder = ExecuteLendOrder::new(
                account_id,
                uuid,
                order_type,
                settle_margin_settle_withdraw,
                order_status,
                execution_price_poolshare_price,
            );
            //let settle_zkos_msg: ZkosSettleMsg = ZkosSettleMsg::new(input.clone(), signature.clone());
            let order_zkos_settle: ExecuteLendOrderZkos =
                ExecuteLendOrderZkos::new(execute_lend, settle_zkos_msg.clone());
            settle_hex = order_zkos_settle.encode_as_hex_string();
        }
    }

    //let msg_to_return = serde_json::to_string(&settle_hex);
    //Ok(msg_to_return.unwrap())
    settle_hex
}

/// Create a ZkosLendOrder from ZkosAccount
///
pub fn create_lend_order_zkos(
    input_coin: String,
    output_memo: String,
    secret_key: RistrettoSecretKey,
    rscalar: String, // Hex string of Scalar
    value: u64,
    account_id: String,
    balance: f64,
    order_type: String,
    order_status: String,
    deposit: f64,
) -> String {
    //prepare data for signature and same value proof
    let input: Input = serde_json::from_str(&input_coin).unwrap();
    let output: Output = serde_json::from_str(&output_memo).unwrap();
    //let scalar_hex: String = serde_json::from_str(&rscalar).unwrap();
    let scalar_bytes = hex::decode(&rscalar).unwrap();
    let rscalar = Scalar::from_bytes_mod_order(scalar_bytes.try_into().unwrap());

    let zkos_order = create_zkos_order(input, output, secret_key, rscalar, value);
    let create_order: CreateLendOrder =
        CreateLendOrder::new(account_id, balance, order_type, order_status, deposit);
    let create_zkos_order_full: CreateLendOrderZkos =
        CreateLendOrderZkos::new(create_order, zkos_order);
    let order_hex: String = create_zkos_order_full.encode_as_hex_string();
    //println!("order_hex: {}", order_hex);
    //let j = serde_json::to_string(&order_hex);
    //let msg_to_return = j.unwrap();
    //Ok(msg_to_return)
    order_hex
}

/// CancelTraderOrderZkos
/// output-> hex string of the query object
pub fn cancel_trader_order_zkos(
    add_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: String,
    order_type: String,
    order_status: String,
) -> String {
    //prepare data for signature and same value proof
    //extract hex address from jstring
    //let add_hex: String = serde_json::from_str(&address).unwrap();
    //extract Address from hex
    let add: Address = Address::from_hex(&add_hex, AddressType::default()).unwrap();
    //recreate uuid
    let uuid: Uuid = serde_json::from_str(&uuid).unwrap();
    //let u_bytes = hex::decode(uuid_hex).unwrap();
    //let uuid: Uuid = Uuid::from_bytes(u_bytes.try_into().unwrap());

    let cancel_order: CancelTraderOrder =
        CancelTraderOrder::new(account_id, uuid, order_type, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk = add.as_coin_address().public_key;
    // the cancel request is the message for Sign
    let message = bincode::serialize(&cancel_order).unwrap();

    let signature: Signature = pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    let cancel_order_msg: ZkosCancelMsg = ZkosCancelMsg::new(add_hex.clone(), signature);
    let cancel_order_zkos: CancelTraderOrderZkos =
        CancelTraderOrderZkos::new(cancel_order, cancel_order_msg);
    let order_hex: String = cancel_order_zkos.encode_as_hex_string();

    //let msg_to_return = serde_json::to_string(&order_hex);
    //Ok(msg_to_return.unwrap())
    order_hex
}

/// QueryTraderOrderZkos
/// gives hex of the query object
pub fn query_trader_order_zkos(
    add_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    order_status: String,
) -> String {
    //prepare data for signature and same value proof
    //extract hex address from jstring
    // let add_hex: String = serde_json::from_str(&address).unwrap();
    //extract Address from hex
    let add: Address = Address::from_hex(&add_hex, AddressType::default()).unwrap();

    let query_order: QueryTraderOrder = QueryTraderOrder::new(account_id, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk = add.as_coin_address().public_key;
    // the cancel request is the message for Sign
    let message = bincode::serialize(&query_order).unwrap();

    let signature: Signature = pk.sign_msg(&message, secret_key, ("PublicKeySign").as_bytes());

    let query_order_msg: ZkosQueryMsg = ZkosQueryMsg::new(add_hex.clone(), signature);
    let query_order_zkos: QueryTraderOrderZkos =
        QueryTraderOrderZkos::new(query_order, query_order_msg);
    let order_hex: String = query_order_zkos.encode_as_hex_string();

    //let msg_to_return = serde_json::to_string(&order_hex);
    //Ok(msg_to_return.unwrap())
    order_hex
}

/// QueryLendOrderZkos
///
pub fn query_lend_order_zkos(
    add_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    order_status: String,
) -> String {
    //extract hex address from jstring
    //let add_hex: String = serde_json::from_str(&address).unwrap();
    //extract Address from hex
    let add: Address = Address::from_hex(&add_hex, AddressType::default()).unwrap();

    let query_lend: QueryLendOrder = QueryLendOrder::new(account_id, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk = add.as_coin_address().public_key;
    // the cancel request is the message for Sign
    let message = bincode::serialize(&query_lend).unwrap();

    let signature: Signature = pk.sign_msg(&message, secret_key, ("PublicKeySign").as_bytes());

    let query_lend_msg: ZkosQueryMsg = ZkosQueryMsg::new(add_hex.clone(), signature);
    let query_lend_zkos: QueryLendOrderZkos = QueryLendOrderZkos::new(query_lend, query_lend_msg);
    let order_hex: String = query_lend_zkos.encode_as_hex_string();

    //let msg_to_return = serde_json::to_string(&order_hex);
    //Ok(msg_to_return.unwrap())
    order_hex
}

/// convert Utxo json Object into Hex String
pub fn get_utxo_hex_from_json(utxo_json: String) -> String {
    let utxo: Utxo = serde_json::from_str(&utxo_json).unwrap();
    let utxo_bytes = bincode::serialize(&utxo).unwrap();
    let utxo_hex = hex::encode(&utxo_bytes);
    utxo_hex
}
