use crate::relayer_types::{
    CancelTraderOrder, CancelTraderOrderZkos, CreateLendOrder, CreateLendOrderZkos,
    CreateTraderOrder, CreateTraderOrderZkos, ExecuteLendOrder, ExecuteLendOrderZkos,
    ExecuteTraderOrder, ExecuteTraderOrderZkos, QueryLendOrder, QueryLendOrderZkos,
    QueryTraderOrder, QueryTraderOrderZkos, TXType, ZkosCancelMsg, ZkosCreateOrder, ZkosQueryMsg,
    ZkosSettleMsg,
};
use address::{Address, AddressType};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use quisquislib::{
    accounts::Account,
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use uuid::Uuid;
use zkschnorr::Signature;
use zkvm::{zkos_types::ValueWitness, Input, Output, Utxo};

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

    // create InputCoin Witness
    let witness = ValueWitness::create_value_witness(
        input.clone(),
        secret_key,
        output.clone(),
        enc_acc,
        pubkey.clone(),
        pedersen_commitment.clone(),
        value,
        rscalar,
    );
    ZkosCreateOrder::new(input, output, witness)
}

///Create a ZkosCreateTraderOrder from ZkosAccount
///
pub fn create_trader_order_zkos(
    input_coin: Input,
    output_memo: Output,
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
) -> Result<String, &'static str> {
    //prepare data for signature and same value proof
    let rscalar = match hex_to_scalar(rscalar) {
        Some(scalar) => scalar,
        None => return Err("Invalid Scalar:: Hex Decode Error "),
    };

    let zkos_order = create_zkos_order(input_coin, output_memo, secret_key, rscalar, value);
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
    let order_hex: String = create_zkos_order_full.encode_as_hex_string();
    Ok(order_hex)
}

/// ExecuteOrderZkos. Used to settle trade or lend orders
/// Input = Memo
/// seed  = private signature to derive secret key
/// rest of the normal settle order message
/// tx_type = "ORDERTX" for settling trader orders
/// tx_type = "LENDTX" for settling lend orders
/// returns hex string of the object
pub fn execute_order_zkos(
    input_memo: Input,
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: Uuid,
    order_type: String,
    settle_margin_settle_withdraw: f64,
    order_status: String,
    execution_price_poolshare_price: f64,
    tx_type: TXType,
) -> String {
    //prepare data for signature and same value proof
    //recreate uuid

    //extract publickey from owner address of input memo
    let owner: String = input_memo.as_owner_address().unwrap().to_owned();
    let pk: RistrettoPublicKey = Address::from_hex(&owner, AddressType::default())
        .unwrap()
        .as_coin_address()
        .public_key;
    // sign the input memo
    let message = bincode::serialize(&input_memo).unwrap();
    let signature: Signature = pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    //Let order type (Trade or Lend)

    let settle_zkos_msg: ZkosSettleMsg = ZkosSettleMsg::new(input_memo.clone(), signature.clone());
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
            let order_zkos_settle: ExecuteLendOrderZkos =
                ExecuteLendOrderZkos::new(execute_lend, settle_zkos_msg.clone());
            settle_hex = order_zkos_settle.encode_as_hex_string();
        }
    }
    settle_hex
}

/// Create a ZkosLendOrder from ZkosAccount
///
pub fn create_lend_order_zkos(
    input_coin: Input,
    output_memo: Output,
    secret_key: RistrettoSecretKey,
    rscalar: String, // Hex string of Scalar
    value: u64,
    account_id: String,
    balance: f64,
    order_type: String,
    order_status: String,
    deposit: f64,
) -> Result<String, &'static str> {
    let rscalar = match hex_to_scalar(rscalar) {
        Some(scalar) => scalar,
        None => return Err("Invalid Scalar:: Hex Decode Error "),
    };

    let zkos_order = create_zkos_order(input_coin, output_memo, secret_key, rscalar, value);
    let create_order: CreateLendOrder =
        CreateLendOrder::new(account_id, balance, order_type, order_status, deposit);
    let create_zkos_order_full: CreateLendOrderZkos =
        CreateLendOrderZkos::new(create_order, zkos_order);
    let order_hex: String = create_zkos_order_full.encode_as_hex_string();
    Ok(order_hex)
}

/// CancelTraderOrderZkos
/// output-> hex string of the query object
pub fn cancel_trader_order_zkos(
    address_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: Uuid,
    order_type: String,
    order_status: String,
) -> String {
    //prepare data for signature and same value proof

    let add: Address = Address::from_hex(&address_hex, AddressType::default()).unwrap();

    let cancel_order: CancelTraderOrder =
        CancelTraderOrder::new(account_id, uuid, order_type, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk: RistrettoPublicKey = add.into();
    // the cancel request is the message for Sign
    let message = bincode::serialize(&cancel_order).unwrap();

    let signature: Signature = pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    let cancel_order_msg: ZkosCancelMsg = ZkosCancelMsg::new(address_hex.clone(), signature);
    let cancel_order_zkos: CancelTraderOrderZkos =
        CancelTraderOrderZkos::new(cancel_order, cancel_order_msg);
    let order_hex: String = cancel_order_zkos.encode_as_hex_string();
    order_hex
}

/// QueryTraderOrderZkos
/// gives hex of the query object
pub fn query_trader_order_zkos(
    address_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    order_status: String,
) -> String {
    //prepare data for signature
    //extract Address from hex
    let add: Address = Address::from_hex(&address_hex, AddressType::default()).unwrap();

    let query_order: QueryTraderOrder = QueryTraderOrder::new(account_id, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk: RistrettoPublicKey = add.into();
    // the cancel request is the message for Sign
    let message = bincode::serialize(&query_order).unwrap();

    let signature: Signature = pk.sign_msg(&message, secret_key, ("PublicKeySign").as_bytes());

    let query_order_msg: ZkosQueryMsg = ZkosQueryMsg::new(address_hex.clone(), signature);
    let query_order_zkos: QueryTraderOrderZkos =
        QueryTraderOrderZkos::new(query_order, query_order_msg);
    let order_hex: String = query_order_zkos.encode_as_hex_string();
    order_hex
}

/// QueryLendOrderZkos
///
pub fn query_lend_order_zkos(
    address_hex: String, //hex address string
    secret_key: &RistrettoSecretKey,
    account_id: String,
    order_status: String,
) -> String {
    //extract Address from hex
    let add: Address = Address::from_hex(&address_hex, AddressType::default()).unwrap();

    let query_lend: QueryLendOrder = QueryLendOrder::new(account_id, order_status);
    //create ZkosCancelMsg
    // pk for Sign
    let pk: RistrettoPublicKey = add.into();
    // the cancel request is the message for Sign
    let message = bincode::serialize(&query_lend).unwrap();

    let signature: Signature = pk.sign_msg(&message, secret_key, ("PublicKeySign").as_bytes());

    let query_lend_msg: ZkosQueryMsg = ZkosQueryMsg::new(address_hex.clone(), signature);
    let query_lend_zkos: QueryLendOrderZkos = QueryLendOrderZkos::new(query_lend, query_lend_msg);
    let order_hex: String = query_lend_zkos.encode_as_hex_string();
    order_hex
}

// Public utility functions used for type conversions
// scalar to hex
pub fn scalar_to_hex(scalar: Scalar) -> String {
    let byt = scalar.to_bytes();
    hex::encode(&byt)
}

/// convert hex string to Scalar
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

/// convert Utxo json Object into Hex String
pub fn get_utxo_hex_from_json(utxo_json: String) -> String {
    let utxo: Utxo = serde_json::from_str(&utxo_json).unwrap();
    let utxo_bytes = bincode::serialize(&utxo).unwrap();
    let utxo_hex = hex::encode(&utxo_bytes);
    utxo_hex
}
