use crate::programcontroller::ContractManager;
use crate::script;
use crate::transaction::{self, ScriptTransaction, Transaction};
use crate::relayer_types::{
    CancelTraderOrder, CancelTraderOrderZkos, CreateLendOrder, CreateLendOrderZkos, CreateTraderOrder, CreateTraderOrderClientZkos, CreateTraderOrderZkos, ExecuteLendOrder, ExecuteLendOrderZkos, ExecuteTraderOrder, ExecuteTraderOrderZkos, PositionType, QueryLendOrder, QueryLendOrderZkos, QueryTraderOrder, QueryTraderOrderZkos, TXType, ZkosCancelMsg, ZkosCreateOrder, ZkosQueryMsg, ZkosSettleMsg
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
use zkvm::{zkos_types::ValueWitness, Input, Output, String as ZkvmString};

///Create a ZkosCreateTraderOrder OR ZkosCreateLendOrder from ZkosAccount
/// Returns ZkosCreateOrder as string
/// input : Input::coin(InputData::coin(utxo, out_coin.clone(), 0));
/// output : Output::memo(OutputData::memo(_memo));
/// seed : Secret key
/// rscalar: Scalar used to create Encryption and Commitment
/// value: value of the order.  Should be equal to the balance of the input otherwise the difference might be burned
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
        //output.clone(),
        // output.clone(),
        enc_acc.clone(),
        pubkey.clone(),
        pedersen_commitment.clone(),
        value,
        rscalar,
    );

    //verify the witness 
  
    let verify_witness = witness.verify_value_witness(input.clone(), pubkey.clone(), enc_acc.clone(), pedersen_commitment);
    println!("verify_witness: {:?}", verify_witness);
    ZkosCreateOrder::new(input, output, witness)
}

///Create a ZkosCreateTraderOrder from ZkosAccount
///
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
    order_side: PositionType,
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
    let contract_address = programs
        .create_contract_address(address::Network::default())?;
    

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
    let order_hex: String = create_zkos_order_full.encode_as_hex_string()?;
    Ok(order_hex)
}

/// ExecuteOrderZkos. Used to settle trade or lend orders
/// Input = Memo(Output) with Prover view
/// seed  = private signature to derive secret key
/// rest of the normal settle order message
/// tx_type = "ORDERTX" for settling trader orders
/// tx_type = "LENDTX" for settling lend orders
/// returns hex string of the object
pub fn execute_order_zkos(
    output_memo: Output, // Provides the Prover Memo Output used to create the order. Input memo will be created by Exchange on behalf of the user
    secret_key: &RistrettoSecretKey,
    account_id: String,
    uuid: Uuid,
    order_type: String,
    settle_margin_settle_withdraw: f64,
    order_status: String,
    execution_price_poolshare_price: f64,
    tx_type: TXType,
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

/// Creates the Script based Transaction for creating the trade order on Client for chain
///
///@param input_coin :  Input Coin from the trader
///@param output_memo : Output Memo created by the trader
/// @return : Transaction
///
pub fn create_trade_order_client_transaction(
    input_coin: Input,    // Input received from the trader
    output_memo: Output, // Output Memo created by the trader (C(Initial Margin), PositionSize, C(Leverage), EntryPrice, OrderSide
    secret_key: RistrettoSecretKey,
    rscalar: Scalar, // Hex string of Scalar
    value: u64, // Margin Value
    position_value: u64, // Position Value
    chain_network: address::Network,
    fee: u64, // in satoshis
    contract_manager: crate::programcontroller::ContractManager,
) -> Result<transaction::Transaction, &'static str> {
    // create same value proof 
    let zkos_order = create_zkos_order(input_coin.clone(), output_memo.clone(), secret_key, rscalar, value);
    
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
    let position_value_string: ZkvmString = crate::util::u64_commitment_to_zkvm_string(position_value);
    let tx_data = Some(position_value_string);
    // execute the program and create a proof for computations
    let program_proof = transaction::vm_run::Prover::build_proof(
        single_program.unwrap(),
        &inputs,
        &outputs,
        false,
        tx_data.clone(),
    );

    println!("program_proof: {:?}", program_proof );

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

    use address::{Address, Network};
    use curve25519_dalek::scalar::Scalar;
    use quisquislib::{
        accounts::Account,
        elgamal::ElGamalCommitment,
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };
    use zkvm::{zkos_types::OutputCoin, Commitment, InputData, OutputData, Utxo, Witness};

    use crate::util;

    use super::*;
    #[test]
    fn test_create_trader_order() {
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
        let mut rng = rand::thread_rng();
        let sk_in: RistrettoSecretKey = RistrettoSecretKey::random(&mut rng);
        let pk_in: RistrettoPublicKey = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);

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
            sk_in,
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
    fn test_settle_trader_order_message() {
        // get private key for the memo
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c7ccfc25ec0c535a8232e785ddec39972dc48e25ae570e368b9384dc6147ec639b4ea7118b0002894c9d2d9bfcaf72d47a0a49893518a4cfb30a0e81ba34a51684e2f05e9";
        // get pk from client address
        let address = Address::from_hex(&client_address, address::AddressType::default()).unwrap();
        let client_pk: RistrettoPublicKey = address.into();

        // get Memo to be sent to the exchange
        // Memo should be the output of the order submitted earlier
        let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a000000000000003063376363666332356563306335333561383233326537383564646563333939373264633438653235616535373065333638623933383464633631343765633633396234656137313138623030303238393463396432643962666361663732643437613061343938393335313861346366623330613065383162613334613531363834653266303565390100000000000000a0860100000000000000000000000000b899875f246706825d9a849a195da763b3718fc2bdf44cc4eccbb447fe484d010104000000000000000300000001000000003c534c1000000000000000000000000000000000000000000000000000000002000000010000000000000014000000000000000000000000000000b899875f246706825d9a849a195da763b3718fc2bdf44cc4eccbb447fe484d010300000001000000b8880000000000000000000000000000000000000000000000000000000000000300000001000000010000000000000000000000000000000000000000000000000000000000000000000000";
        let memo_bin = hex::decode(memo_hex).unwrap();
        let memo: Output = bincode::deserialize(&memo_bin).unwrap();
        // UPDATE VALUES HERE
        let settle_msg = execute_order_zkos(
            memo.clone(),
            &sk,
            "account_id".to_string(),
            Uuid::new_v4(),
            "MARKET".to_string(),
            100000.0,
            "PENDING".to_string(),
            35000.0,
            TXType::ORDERTX,
        );

        println!("settle_msg: {:?}", settle_msg);
    }

    #[test]
    pub fn test_create_lend_order_data() {
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c7ccfc25ec0c535a8232e785ddec39972dc48e25ae570e368b9384dc6147ec639b4ea7118b0002894c9d2d9bfcaf72d47a0a49893518a4cfb30a0e81ba34a51684e2f05e9";

        let path = "./relayerprogram.json";
        let programs = crate::programcontroller::ContractManager::import_program(path);
        let contract_address = programs
            .create_contract_address(Network::default())
            .unwrap();

        let scalar_hex = "b899875f246706825d9a849a195da763b3718fc2bdf44cc4eccbb447fe484d01";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
        let deposit = 1000000u64;

        let out_coin = util::create_output_coin_for_trader(
            client_address.to_string(),
            deposit,
            scalar_hex.to_string(),
        )
        .unwrap();
        let input_coin = util::create_input_coin_from_output_coin(
            out_coin,
            serde_json::to_string(&Utxo::default()).unwrap(),
        )
        .unwrap();

        let pool_share = 1000000u64;
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
    fn test_settle_lend_order_message() {
        // get private key for the memo
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());

        // get Memo to be sent to the exchange
        // Memo should be the output of the order submitted earlier
        let memo_hex = "01000000010000002a000000000000003138663265626461313733666663366164326533623464336133383634613936616538613666376533308a000000000000003063376363666332356563306335333561383233326537383564646563333939373264633438653235616535373065333638623933383464633631343765633633396234656137313138623030303238393463396432643962666361663732643437613061343938393335313861346366623330613065383162613334613531363834653266303565390100000000000000a0860100000000000000000000000000b899875f246706825d9a849a195da763b3718fc2bdf44cc4eccbb447fe484d010104000000000000000300000001000000003c534c1000000000000000000000000000000000000000000000000000000002000000010000000000000014000000000000000000000000000000b899875f246706825d9a849a195da763b3718fc2bdf44cc4eccbb447fe484d010300000001000000b8880000000000000000000000000000000000000000000000000000000000000300000001000000010000000000000000000000000000000000000000000000000000000000000000000000";
        let memo_bin = hex::decode(memo_hex).unwrap();
        let memo: Output = bincode::deserialize(&memo_bin).unwrap();
        // UPDATE VALUES HERE
        let settle_msg = execute_order_zkos(
            memo.clone(),
            &sk,
            "account_id".to_string(),
            Uuid::new_v4(),
            "MARKET".to_string(),
            100000.0,
            "PENDING".to_string(),
            35000.0,
            TXType::ORDERTX,
        );

        println!("settle_msg: {:?}", settle_msg);
    }
    
    #[test]
    pub fn test_create_trader_order_client_tx() {

        let mut rng = rand::thread_rng();
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
        let sk_in = SecretKey::from_bytes(seed.as_bytes());

        let pk_in: RistrettoPublicKey = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);

        let add: Address = Address::standard_address(Network::default(), pk_in.clone());
        let rscalar: Scalar = Scalar::random(&mut rng);
        let value = 100000u64;
        
        // create input coin
        let commit_in =
            ElGamalCommitment::generate_commitment(&pk_in, rscalar, Scalar::from(value));
        let enc_acc = Account::set_account(pk_in, commit_in);

        let coin = OutputCoin {
            encrypt: commit_in,
            owner: add.as_hex(),
        };
        let in_data: InputData = InputData::coin(Utxo::default(), coin, 0);
        let coin_in: Input = Input::coin(in_data.clone());
        
        let leverage = 10.0;
        let position_value = value * leverage as u64;
        let entry_price = 56436u64;
        let position_size = position_value * entry_price;
        let order_side = PositionType::LONG;
        let contract_path = "./relayerprogram.json";
        
        let programs = crate::programcontroller::ContractManager::import_program(&contract_path);

        let order_tx_message = create_trader_order_zkos(
            coin_in.clone(),
            sk_in,
            rscalar,
            value,
            order_side.to_str(),
            "MARKET".to_string(),
            leverage,
            value as f64,
            value as f64,
            "PENDING".to_string(),
            entry_price as f64,
            35000.0,
            position_value,
            position_size,
            order_side,
            &programs,
            0u32,
        );
        println!("order_hex: {:?}", order_tx_message);

        // recreate clientZkos struct
        let client_zkos = CreateTraderOrderClientZkos::decode_from_hex_string(order_tx_message.unwrap()).unwrap();
        let order_tx = client_zkos.tx;
        // verify the transaction
        let verify_tx = order_tx.verify();
        println!("verify_tx: {:?}", verify_tx);
        // println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }
}
