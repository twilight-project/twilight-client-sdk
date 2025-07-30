//! Provides the high-level API for interacting with the Twilight Relayer.
//!
//! This module contains all the necessary functions for creating, executing, canceling,
//! and querying both trade and lend orders. It abstracts away the low-level details of
//! message signing and data serialization required for authenticated communication
//! with the relayer service.
use crate::{
    programcontroller::ContractManager,
    relayer_types::{
        CancelTraderOrder, CancelTraderOrderZkos, CreateLendOrder, CreateLendOrderZkos,
        CreateTraderOrder, CreateTraderOrderClientZkos, ExecuteLendOrder, ExecuteLendOrderZkos,
        ExecuteTraderOrder, ExecuteTraderOrderZkos, QueryLendOrder, QueryLendOrderZkos,
        QueryTraderOrder, QueryTraderOrderZkos, TXType, ZkosCancelMsg, ZkosCreateOrder,
        ZkosQueryMsg, ZkosSettleMsg,
    },
};
use address::{Address, AddressType};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use quisquislib::{
    accounts::Account,
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use transaction::{ScriptTransaction, Transaction};
use uuid::Uuid;
use zkschnorr::Signature;
use zkvm::{zkos_types::ValueWitness, Input, Output, String as ZkvmString};

/// A utility function to create the core `ZkosCreateOrder` component.
///
/// This helper function generates the `ValueWitness` required to prove that the value
/// in the input coin is the same as the value committed to in the output memo, without

/// revealing the actual value. This proof is a fundamental part of creating any
/// ZkOS-based order.
///
/// # Parameters
/// - `input`: The `Input::coin` to be spent for the order.
/// - `output`: The `Output::memo` containing the committed value and order details.
/// - `secret_key`: The secret key of the owner of the input coin.
/// - `rscalar`: The random scalar used to create the encryption and commitment in the output.
/// - `value`: The actual value of the order, which must match the balance of the `input`.
///
/// # Returns
/// A `ZkosCreateOrder` struct containing the input, output, and the generated witness.
///
/// # Panics
/// Panics if the provided addresses or outputs are not of the expected type (e.g., if `output` is not a memo).
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
        // output.clone(),
        enc_acc,
        pubkey.clone(),
        pedersen_commitment.clone(),
        value,
        rscalar,
    );
    ZkosCreateOrder::new(input, output, witness)
}

/// Constructs and serializes a message to create a new trader order.
///
/// This function bundles all trader order parameters with the necessary ZK proofs
/// into a single hex-encoded string ready to be sent to the relayer.
///
/// # Parameters
/// - `input_coin`: The `Input` coin UTXO to fund the order's margin.
/// - `output_memo`: The `Output` memo containing the committed order details.
/// - `secret_key`: The trader's secret key.
/// - `rscalar`: The hex-encoded random scalar used for the memo's commitments.
/// - `value`: The amount of initial margin, which must match the `input_coin`'s value.
/// - `account_id`: The user's account identifier on the relayer.
/// - `position_type`: The order side ("LONG" or "SHORT").
/// - `order_type`: The type of order (e.g., "MARKET").
/// - `leverage`: The leverage for the trade.
/// - `initial_margin`: The initial margin amount.
/// - `available_margin`: The available margin.
/// - `order_status`: The initial status of the order (e.g., "PENDING").
/// - `entryprice`: The desired entry price for the trade.
/// - `execution_price`: The execution price (typically set by the relayer).
///
/// # Returns
/// A `Result` containing the hex-encoded `CreateTraderOrderZkos` message string,
/// or an error if the scalar decoding fails.
pub fn create_trader_order_zkos(
    input_coin: Input,
    secret_key: RistrettoSecretKey,
    rscalar: Scalar, // Hex string of Scalar
    value: u64,
    position_type: String,
    order_type: String,
    leverage: f64,
    initial_margin: f64,
    available_margin: f64,
    order_status: String,
    entryprice: f64,
    execution_price: f64,
    position_value: u64,
    position_size: u64,
    order_side: crate::relayer_types::PositionType,
    programs: &ContractManager,
    timebounds: u32,
) -> Result<String, &'static str> {
    // extract owner address from input
    let owner_address = match input_coin.as_owner_address() {
        Some(owner_address) => owner_address.clone(),
        None => return Err("Error extracting owner address"),
    };

    // create TraderOrder type for relayer
    let create_order: CreateTraderOrder = CreateTraderOrder::new(
        owner_address.clone(),
        position_type,
        order_type,
        leverage,
        initial_margin,
        available_margin,
        order_status,
        entryprice,
        execution_price,
    );
    // create Trader Order transaction

    // load the contract_manager
    //let programs = crate::programcontroller::ContractManager::import_program(&contract_path);
    let contract_address = programs.create_contract_address(address::Network::default())?;

    // create memo output
    let memo = crate::util::create_output_memo_for_trader(
        contract_address,
        owner_address,
        value,
        position_size,
        leverage as u64,
        entryprice as u64,
        order_side,
        rscalar,
        timebounds,
    );

    // create ZkOrder transaction
    let order_tx = create_trade_order_client_transaction(
        input_coin,
        memo,
        secret_key,
        rscalar,
        value,
        position_value,
        address::Network::default(),
        1u64,
        programs.clone(),
    )?;

    let create_zkos_order_full: CreateTraderOrderClientZkos =
        CreateTraderOrderClientZkos::new(create_order, order_tx);
    let order_hex: String = match create_zkos_order_full.encode_as_hex_string() {
        Ok(order_hex) => order_hex,
        Err(_) => return Err("Error encoding order as hex string"),
    };
    Ok(order_hex)
}

/// Constructs and serializes a message to execute (settle) a trade or lend order.
///
/// This function signs the original `OutputMemo` created for the order to prove ownership
/// and authorize the relayer to proceed with settlement. The `tx_type` parameter
/// determines whether it's a trade or lend order settlement.
///
/// # Parameters
/// - `output_memo`: The original `OutputMemo` that was used to create the order.
/// - `secret_key`: The secret key of the user who owns the memo.
/// - `account_id`: The user's account identifier.
/// - `uuid`: The `Uuid` of the specific order to be executed.
/// - `order_type`: The type of the order (e.g., "MARKET").
/// - `settle_margin_settle_withdraw`: The margin to settle or amount to withdraw.
/// - `order_status`: The expected status after settlement (e.g., "FILLED").
/// - `execution_price_poolshare_price`: The final execution price or pool share price.
/// - `tx_type`: The type of transaction, `TXType::ORDERTX` for trades or `TXType::LENDTX` for lending.
///
/// # Returns
/// A hex-encoded string of the `ExecuteTraderOrderZkos` or `ExecuteLendOrderZkos` message.
///
/// # Panics
/// Panics on serialization errors or if the owner address is invalid.
pub fn execute_order_zkos(
    output_memo: Output, // Provides the Prover Memo Output used to create the order. Input memo will be created by Exchange on behalf of the user
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: Uuid,
    order_type: String,
    settle_margin_settle_withdraw: f64, //random value =0
    order_status: String,
    execution_price_poolshare_price: f64,
    tx_type: TXType, // ORDER or LEND
) -> String {
    //prepare data for signature
    //extract publickey from owner address of output memo
    let owner_address_string = output_memo.as_output_data().get_owner_address().unwrap();
    let owner: Address = Address::from_hex(&owner_address_string, AddressType::default()).unwrap();
    let pk: RistrettoPublicKey = owner.into();

    // sign the input memo
    let message = bincode::serialize(&output_memo).unwrap();
    let signature: Signature = pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    //Let order type (Trade or Lend)

    let settle_zkos_msg: ZkosSettleMsg = ZkosSettleMsg::new(output_memo.clone(), signature.clone());

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
            return order_zkos_settle.encode_as_hex_string();
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
            return order_zkos_settle.encode_as_hex_string();
        }
    }
}

/// Constructs and serializes a message to create a new lend order.
///
/// This function bundles all lend order parameters with the necessary ZK proofs
/// into a single hex-encoded string ready to be sent to the relayer.
///
/// # Parameters
/// - `input_coin`: The `Input` coin UTXO to fund the lend order.
/// - `output_memo`: The `Output` memo containing the committed deposit details.
/// - `secret_key`: The lender's secret key.
/// - `rscalar`: The hex-encoded random scalar used for the memo's commitments.
/// - `value`: The deposit amount, which must match the `input_coin`'s value.
/// - `account_id`: The user's account identifier on the relayer.
/// - `balance`: The user's balance.
/// - `order_type`: The type of order (e.g., "LEND").
/// - `order_status`: The initial status of the order (e.g., "PENDING").
/// - `deposit`: The amount to deposit.
///
/// # Returns
/// A `Result` containing the hex-encoded `CreateLendOrderZkos` message string,
/// or an error if the scalar decoding fails.
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
    let rscalar = match crate::util::hex_to_scalar(rscalar) {
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

/// Constructs and serializes a message to cancel a pending trader order.
///
/// The function signs the cancellation request with the user's secret key to
/// authorize the action.
///
/// # Parameters
/// - `address_hex`: The user's hex-encoded public address string.
/// - `secret_key`: The user's secret key for signing.
/// - `account_id`: The user's account identifier.
/// - `uuid`: The `Uuid` of the order to cancel.
/// - `order_type`: The type of the order.
/// - `order_status`: The new desired status (e.g., "CANCELLED").
///
/// # Returns
/// A hex-encoded string of the `CancelTraderOrderZkos` message.
///
/// # Panics
/// Panics on address decoding or serialization errors.
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

/// Constructs and serializes a message to query the status of trader orders.
///
/// The query is signed with the user's secret key to ensure only the owner
/// can query their orders.
///
/// # Parameters
/// - `address_hex`: The user's hex-encoded public address string.
/// - `secret_key`: The user's secret key for signing.
/// - `account_id`: The user's account identifier.
/// - `order_status`: The status of orders to query (e.g., "PENDING", "FILLED").
///
/// # Returns
/// A hex-encoded string of the `QueryTraderOrderZkos` message.
///
/// # Panics
/// Panics on address decoding or serialization errors.
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

/// Constructs and serializes a message to query the status of lend orders.
///
/// The query is signed with the user's secret key to ensure only the owner
/// can query their orders.
///
/// # Parameters
/// - `address_hex`: The user's hex-encoded public address string.
/// - `secret_key`: The user's secret key for signing.
/// - `account_id`: The user's account identifier.
/// - `order_status`: The status of orders to query (e.g., "PENDING", "FILLED").
///
/// # Returns
/// A hex-encoded string of the `QueryLendOrderZkos` message.
///
/// # Panics
/// Panics on address decoding or serialization errors.
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

/// Creates the Script based Transaction for creating the trade order on Client for chain
///
///@param input_coin :  Input Coin from the trader
///@param output_memo : Output Memo created by the trader
/// @return : Transaction
///
pub fn create_trade_order_client_transaction(
    input_coin: Input,   // Input received from the trader
    output_memo: Output, // Output Memo created by the trader (C(Initial Margin), PositionSize, C(Leverage), EntryPrice, OrderSide
    secret_key: RistrettoSecretKey,
    rscalar: Scalar,     // Hex string of Scalar
    value: u64,          // Margin Value
    position_value: u64, // Position Value
    chain_network: address::Network,
    fee: u64, // in satoshis
    contract_manager: crate::programcontroller::ContractManager,
) -> Result<transaction::Transaction, &'static str> {
    // create same value proof
    let zkos_order = create_zkos_order(
        input_coin.clone(),
        output_memo.clone(),
        secret_key,
        rscalar,
        value,
    );

    //create Value witness as the witness for coin input
    let witness = zkvm::Witness::ValueWitness(ValueWitness::set_value_witness(
        zkos_order.signature.clone(),
        zkos_order.proof.clone(),
    ));

    let witness_vec = vec![witness];

    //create input vector
    let inputs = vec![input_coin];

    //create output vector
    let outputs = vec![output_memo];

    // get the program from the contract manager
    let order_tag = "CreateTraderOrder";

    let single_program = contract_manager.get_program_by_tag(order_tag);
    // println!("single_program: {:?}", single_program);

    // create positionValue as String
    let position_value_string: ZkvmString =
        crate::util::u64_commitment_to_zkvm_string(position_value);
    let tx_data = Some(position_value_string);
    // execute the program and create a proof for computations
    let program_proof = transaction::vm_run::Prover::build_proof(
        single_program.unwrap(),
        &inputs,
        &outputs,
        false,
        tx_data.clone(),
    );

    // println!("program_proof: {:?}", program_proof );

    let (program, proof) = match program_proof {
        Ok((program, proof)) => (program, proof),
        Err(_) => return Err("Error in creating program proof"),
    };

    // converts inputs and outputs to hide the encrypted data using verifier view and update witness index
    //let (inputs, outputs, tx_data) = ScriptTransaction::create_verifier_view(&inputs, &outputs, Some(position_value_string));

    // create callproof for the program
    let call_proof = contract_manager.create_call_proof(chain_network, order_tag)?;

    // verify the r1cs proof
    // let verify = transaction::vm_run::Verifier::verify_r1cs_proof(
    //     &proof,
    //     &program,
    //     &inputs,
    //     &outputs,
    //     false,
    //     tx_data.clone(),
    // );
    // println!("verify Program proof: {:?}", verify);

    let script_tx = ScriptTransaction::set_script_transaction(
        0u64,
        fee,
        0u64,
        inputs.len() as u8,
        outputs.len() as u8,
        witness_vec.len() as u8,
        inputs.to_vec(),
        outputs.to_vec(),
        program,
        call_proof,
        proof,
        witness_vec.to_vec(),
        tx_data.clone(),
    );

    // let verify_call_proof = script_tx.verify_call_proof();
    // println!("verify_call_proof: {:?}", verify_call_proof);

    Ok(Transaction::from(script_tx))
}

#[cfg(test)]
mod test {

    use crate::relayer_types;
    use crate::relayer_types::CreateTraderOrderZkos;
    use address::{Address, Network};
    use curve25519_dalek::scalar::Scalar;
    use quisquislib::{
        accounts::Account,
        elgamal::ElGamalCommitment,
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };
    use rand::rngs::OsRng;
    use zkvm::{zkos_types::OutputCoin, Commitment, InputData, OutputData, Utxo, Witness};

    use super::*;
    #[test]
    fn test_create_trader_order() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let create_trader_order: CreateTraderOrder = CreateTraderOrder::new(
            "account_id".to_string(),
            "LONG".to_string(),
            "MARKET".to_string(),
            10.0,
            10.0,
            10.0,
            "PENDING".to_string(),
            30000.0,
            30000.0,
        );
        // create input coin
        //create InputCoin and OutputMemo
        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");
        let mut rng = OsRng;
        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let pk_in: RistrettoPublicKey = RistrettoPublicKey::from_secret_key(&sk, &mut rng);

        let add: Address = Address::standard_address(Network::default(), pk_in.clone());
        let rscalar: Scalar = Scalar::random(&mut rng);
        // create input coin
        let commit_in =
            ElGamalCommitment::generate_commitment(&pk_in, rscalar, Scalar::from(10u64));
        let enc_acc = Account::set_account(pk_in, commit_in);

        let coin = OutputCoin {
            encrypt: commit_in,
            owner: add.as_hex(),
        };
        let in_data: InputData = InputData::coin(Utxo::default(), coin, 0);
        let coin_in: Input = Input::coin(in_data.clone());

        //create first Commitment Witness
        let commit_1: Commitment = Commitment::blinded_with_factor(10u64, rscalar);
        let (_comit_1_value, _comit_1_blind) = commit_1.witness().unwrap();

        //create OutputMemo

        let out_memo = zkvm::zkos_types::OutputMemo {
            script_address: add.as_hex(),
            owner: add.as_hex(),
            commitment: commit_1.clone(),
            data: None,
            timebounds: 0,
        };
        let out_memo = Output::memo(OutputData::memo(out_memo));
        let memo_commitment_point = commit_1.to_point();
        // create InputCoin Witness
        let witness = Witness::ValueWitness(ValueWitness::create_value_witness(
            coin_in.clone(),
            sk,
            //  out_memo.clone(),
            enc_acc,
            pk_in.clone(),
            memo_commitment_point.clone(),
            10u64,
            rscalar,
        ));

        // verify the witness
        let value_wit = witness.to_value_witness().unwrap();
        let zkos_create_trader_order = ZkosCreateOrder::new(coin_in, out_memo, value_wit);
        let order_msg: CreateTraderOrderZkos = CreateTraderOrderZkos {
            create_trader_order: create_trader_order,
            input: zkos_create_trader_order,
        };

        println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }

    #[test]
    pub fn test_create_trader_order_broadcast_data() {
        dotenvy::dotenv().expect("Failed loading dotenv");

        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c24765b08a2ac4ce30a3e51ca1a3a16395c8c8499f0dc705275b2512ea78e216eb48f512e1db7d7b048a6827d43cad0e921517c22844b758bb518213e7b295c36a0fab02a";
        // get pk from client address
        // let address = Address::from_hex(&client_address, address::AddressType::default()).unwrap();
        // let client_pk: RistrettoPublicKey = address.into();

        let path = "./relayerprogram.json";
        let programs = crate::programcontroller::ContractManager::import_program(path);
        let contract_address = programs
            .create_contract_address(Network::default())
            .unwrap();
        let input_coin =
            crate::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        // get encryption from input coin to check if we got the correct input coin
        let enc_acc = input_coin.to_quisquis_account().unwrap();
        let key = enc_acc.decrypt_account_balance(&sk, Scalar::from(232504500u64));
        println!("G ^ balance :{:?}", key);
        let scalar_hex = "b49f4a5fc26cfdb4e556675860bd7b56af7952d455975c73981a0e2dafe51d05";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();

        let position_side = crate::relayer_types::PositionType::LONG;
        let output_memo = crate::util::create_output_memo_for_trader(
            contract_address,
            client_address.to_string(),
            232504500,
            70000000000,
            20,
            35000,
            position_side.clone(),
            rscalar,
            0u32,
        );
        //convert output_memo to hex to be reused for settlement
        let output_memo_bin = bincode::serialize(&output_memo.clone()).unwrap();
        let output_memo_hex = hex::encode(&output_memo_bin);
        println!("\n output_memo_hex: {:?} \n", output_memo_hex);

        // get commitment from output memo
        //let commitment = output_memo.as_output_data().get_commitment().unwrap();
        //let memo_commitment_point = commitment.to_point();
        // create InputCoin Witness
        // let witness = Witness::ValueWitness(ValueWitness::create_value_witness(
        //     input_coin.clone(),
        //     sk,
        //     output_memo.clone(),
        //     enc_acc,
        //     client_pk.clone(),
        //     memo_commitment_point.clone(),
        //     7000u64,
        //     rscalar,
        // ));
        // verify the witness
        // let value_wit = witness.to_value_witness().unwrap();
        //  let verify= value_wit.verify_value_witness(input, output, pubkey, enc_acc, commitment)
        // let zkos_create_trader_order =
        //   ZkosCreateOrder::new(input_coin.clone(), output_memo.clone(), value_wit);

        // let create_trader_order: CreateTraderOrder = CreateTraderOrder::new(
        //     "account_id".to_string(),
        //     "LONG".to_string(),
        //     "MARKET".to_string(),
        //     20.0,
        //     100000.0,
        //     100000.0,
        //     "PENDING".to_string(),
        //     35000.0,
        //     35000.0,
        // );

        // let order_msg: CreateTraderOrderZkos = CreateTraderOrderZkos {
        //   create_trader_order,
        // input: zkos_create_trader_order,
        // };
        // let order_message = create_trader_order_zkos(
        //     input_coin.clone(),
        //     output_memo.clone(),
        //     sk,
        //     scalar_hex.to_string(),
        //     232504500u64,
        //     "account_id".to_string(),
        //     position_side.to_str(),
        //     "MARKET".to_string(),
        //     20.0,
        //     232504500.0,
        //     232504500.0,
        //     "PENDING".to_string(),
        //     35000.0,
        //     35000.0,
        // );
        // println!("order_hex: {:?}", order_message);
        // println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }

    #[test]
    fn test_settle_trader_order_message() {
        dotenvy::dotenv().expect("Failed loading dotenv");

        // get private key for the memo
        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c24765b08a2ac4ce30a3e51ca1a3a16395c8c8499f0dc705275b2512ea78e216eb48f512e1db7d7b048a6827d43cad0e921517c22844b758bb518213e7b295c36a0fab02a";
        // get pk from client address
        let address = Address::from_hex(&client_address, address::AddressType::default()).unwrap();
        let _client_pk: RistrettoPublicKey = address.into();

        // get Memo to be sent to the exchange
        // Memo should be the output of the order submitted earlier
        let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a000000000000003063323437363562303861326163346365333061336535316361316133613136333935633863383439396630646337303532373562323531326561373865323136656234386635313265316462376437623034386136383237643433636164306539323135313763323238343462373538626235313832313365376232393563333661306661623032610100000000000000b4bcdb0d000000000000000000000000b49f4a5fc26cfdb4e556675860bd7b56af7952d455975c73981a0e2dafe51d050104000000000000000300000001000000203381a474b7000000000000000000000000000000000000000000000000000002000000010000000000000014000000000000000000000000000000b49f4a5fc26cfdb4e556675860bd7b56af7952d455975c73981a0e2dafe51d05030000000100000072a90000000000000000000000000000000000000000000000000000000000000300000001000000ecd3f55c1a631258d69cf7a2def9de140000000000000000000000000000001000000000";
        let memo_bin = hex::decode(memo_hex).unwrap();
        let memo: Output = bincode::deserialize(&memo_bin).unwrap();
        // UPDATE VALUES HERE
        let settle_msg = execute_order_zkos(
            memo.clone(),
            &sk,
            "account_id".to_string(),
            Uuid::parse_str("7bff7290-19f4-4ff3-a664-df0127a89b5a").unwrap(),
            "MARKET".to_string(),
            100000.0,
            "PENDING".to_string(),
            35000.0,
            TXType::ORDERTX,
        );

        println!("settle_msg: {:?}", settle_msg);
    }

    #[test]
    pub fn test_create_lend_order_broadcast_data() {
        dotenvy::dotenv().expect("Failed loading dotenv");

        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c34a200332649c96554331346046e70eaf568f65be5ebfc42f6c20333ca432d7cb8d6bb642432d57cc930fac1a317036dcdaa58edea6e37064485b498abafea1b600bb6c5";

        let path = "./relayerprogram.json";
        let programs = crate::programcontroller::ContractManager::import_program(path);
        let contract_address = programs
            .create_contract_address(Network::default())
            .unwrap();
        let input_coin =
            crate::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        let scalar_hex = "4cfe07c5d225f9cb0a01ff0161077711b63a69fc9f9c35d62b177063d19fa407";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
        let deposit = 1050000000u64;
        let pool_share = 105000u64;
        let output_memo = crate::util::create_output_memo_for_lender(
            contract_address,
            client_address.to_string(),
            deposit,
            pool_share,
            rscalar,
            0u32,
        );
        //convert output_memo to hex to be reused for settlement
        let output_memo_bin = bincode::serialize(&output_memo.clone()).unwrap();
        let output_memo_hex = hex::encode(&output_memo_bin);
        println!("\n output_memo_hex: {:?} \n", output_memo_hex);

        let order_message = create_lend_order_zkos(
            input_coin.clone(),
            output_memo.clone(),
            sk,
            scalar_hex.to_string(),
            deposit,
            "account_id".to_string(),
            deposit as f64,
            "LEND".to_string(),
            "PENDING".to_string(),
            deposit as f64,
        );
        println!("order_hex: {:?}", order_message);
        // println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }
    #[test]
    pub fn test_create_lend_order_broadcast_data1() {
        dotenvy::dotenv().expect("Failed loading dotenv");

        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0cc26cb224c49c39df96de866eb423c78f5ee74912eaf5d0d6c80b6d66d7b5fc3b52822defde2549af70df85fcdbe432b2f2ecce68ae21cc7dbc586734e2569b15700db086";

        let path = "./relayerprogram.json";
        let programs = crate::programcontroller::ContractManager::import_program(path);
        let contract_address = programs
            .create_contract_address(Network::default())
            .unwrap();
        let input_coin =
            crate::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        let scalar_hex = "7ec4718affbd0d996c1e2cfb8573de8e4992b675165fdb5c5c9ff312e036b80f";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
        let deposit = 304060005u64;
        let pool_share = 30406u64;
        let output_memo = crate::util::create_output_memo_for_lender(
            contract_address,
            client_address.to_string(),
            deposit,
            pool_share,
            rscalar,
            0u32,
        );
        //convert output_memo to hex to be reused for settlement
        let output_memo_bin = bincode::serialize(&output_memo.clone()).unwrap();
        let output_memo_hex = hex::encode(&output_memo_bin);
        println!("\n output_memo_hex: {:?} \n", output_memo_hex);

        let order_message = create_lend_order_zkos(
            input_coin.clone(),
            output_memo.clone(),
            sk,
            scalar_hex.to_string(),
            deposit,
            "account_id".to_string(),
            deposit as f64,
            "LEND".to_string(),
            "PENDING".to_string(),
            deposit as f64,
        );
        println!("order_hex: {:?}", order_message);
        // println!("order_hex: {:?}", order_msg.encode_as_hex_string());
        // hex for settle 01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306363323663623232346334396333396466393664653836366562343233633738663565653734393132656166356430643663383062366436366437623566633362353238323264656664653235343961663730646638356663646265343332623266326563636536386165323163633764626335383637333465323536396231353730306462303836010000000000000065961f120000000000000000000000007ec4718affbd0d996c1e2cfb8573de8e4992b675165fdb5c5c9ff312e036b80f0101000000000000000200000001000000000000007c7600000000000000000000000000007ec4718affbd0d996c1e2cfb8573de8e4992b675165fdb5c5c9ff312e036b80f00000000
    }

    #[test]
    fn test_settle_lend_order_message() {
        // get private key for the memo
        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());

        // get Memo to be sent to the exchange
        // Memo should be the output of the order submitted earlier
        let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306333346132303033333236343963393635353433333133343630343665373065616635363866363562653565626663343266366332303333336361343332643763623864366262363432343332643537636339333066616331613331373033366463646161353865646561366533373036343438356234393861626166656131623630306262366335010000000000000080ba953e0000000000000000000000004cfe07c5d225f9cb0a01ff0161077711b63a69fc9f9c35d62b177063d19fa407010100000000000000020000000100000000000000299901000000000000000000000000004cfe07c5d225f9cb0a01ff0161077711b63a69fc9f9c35d62b177063d19fa40700000000";
        let memo_bin = hex::decode(memo_hex).unwrap();
        let memo: Output = bincode::deserialize(&memo_bin).unwrap();
        // UPDATE VALUES HERE
        let settle_msg = execute_order_zkos(
            memo.clone(),
            &sk,
            "account_id".to_string(),
            Uuid::parse_str("f30ece0c-58a2-4f5c-8c56-6ef8348bc18f").unwrap(),
            "MARKET".to_string(),
            100000.0,
            "PENDING".to_string(),
            35000.0,
            TXType::ORDERTX,
        );

        println!("settle_msg: {:?}", settle_msg);
    }
    #[test]
    fn test_settle_lend_order_message1() {
        // get private key for the memo
        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());

        // get Memo to be sent to the exchange
        // Memo should be the output of the order submitted earlier
        let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a00000000000000306363323663623232346334396333396466393664653836366562343233633738663565653734393132656166356430643663383062366436366437623566633362353238323264656664653235343961663730646638356663646265343332623266326563636536386165323163633764626335383637333465323536396231353730306462303836010000000000000065961f120000000000000000000000007ec4718affbd0d996c1e2cfb8573de8e4992b675165fdb5c5c9ff312e036b80f0101000000000000000200000001000000000000007c7600000000000000000000000000007ec4718affbd0d996c1e2cfb8573de8e4992b675165fdb5c5c9ff312e036b80f00000000";
        let memo_bin = hex::decode(memo_hex).unwrap();
        let memo: Output = bincode::deserialize(&memo_bin).unwrap();
        // UPDATE VALUES HERE
        let settle_msg = execute_order_zkos(
            memo.clone(),
            &sk,
            "account_id".to_string(),
            Uuid::parse_str("9c9df814-d386-45fa-b31b-73070707f984").unwrap(),
            "MARKET".to_string(),
            100000.0,
            "PENDING".to_string(),
            35000.0,
            TXType::ORDERTX,
        );

        println!("settle_msg: {:?}", settle_msg);
    }

    #[test]
    fn test_convert_hex_for_utxo() {
        let raw_json = r#"{"output_index":1,"txid":[49,22,252,55,83,210,158,68,59,154,91,209,184,186,150,197,91,105,17,107,16,9,81,52,201,216,75,162,63,81,44,146]}"#;
        let derser_utxo: Utxo = serde_json::from_str(&raw_json).unwrap();
        println!(
            "utxo: {:?}",
            hex::encode(bincode::serialize(&derser_utxo).unwrap())
        );
    }
    #[test]
    fn test_convert_hex_for_output() {
        let raw_json = r#"{"out_type":"State","output":{"State":{"nonce":4,"script_address":"18f2ebda173ffc6ad2e3b4d3a3864a96ae8a6f7e30","owner":"0ca01385e8e9cea89a187e0b0ab2b1caaf713df527acdb88f764358d8d657db34ca2df7eb6c3673d2c7b34c836e5c5bb4fc1d91df3185a576084134bd8ff120d1b9e2eebef","commitment":{"Open":{"value":{"Integer":21098615383},"blinding":[241,214,104,22,41,116,102,48,46,94,109,78,45,30,217,2,36,125,169,15,83,79,81,49,242,108,100,237,86,52,91,1]}},"state_variables":[{"Commitment":{"Open":{"value":{"Integer":2104745},"blinding":[105,97,110,122,21,64,251,162,239,200,159,245,119,18,250,49,104,202,110,72,247,29,44,230,69,198,4,207,135,172,30,15]}}}],"timebounds":0}}}"#;
        let derser_utxo: Output = serde_json::from_str(&raw_json).unwrap();
        println!(
            "output: {:?}",
            hex::encode(bincode::serialize(&derser_utxo).unwrap())
        );
    }

    #[test]
    pub fn test_query_trader_order_broadcast_data() {
        dotenvy::dotenv().expect("Failed loading dotenv");

        let seed = std::env::var("TEST_SEED").expect("Failed to load SEED from .env");

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c542afdbbd1c818b591fd4d8ac92d0c524ba6dfad6f7602a97948ffa443971d5d4820ae39a02b1a6e1310e217c36368865a4fd8144779924d194ca3980a4a8c2101c339a4";

        let order_message = query_trader_order_zkos(
            client_address.to_string().clone(), //hex address string
            &sk,
            client_address.to_string(),
            "PENDING".to_string(),
        );
        println!("order_hex: {:?}", order_message);
    }
}
