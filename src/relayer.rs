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
        // output.clone(),
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
    let rscalar = match crate::util::hex_to_scalar(rscalar) {
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

#[cfg(test)]
mod test {
    use std::f32::MIN_POSITIVE;

    use address::{Address, Network};
    use curve25519_dalek::scalar::{self, Scalar};
    use quisquislib::{
        accounts::Account,
        elgamal::ElGamalCommitment,
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };
    use zkvm::{zkos_types::OutputCoin, Commitment, InputData, OutputData, Utxo, Witness};

    use crate::{keys_management, relayer_types};

    use super::*;
    #[test]
    fn test_create_trader_order() {
        dotenv::dotenv().expect("Failed loading dotenv");
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
    pub fn test_create_trader_order_broadcast_data() {
        dotenv::dotenv().expect("Failed loading dotenv");

        // // get private key from keys management
        // let sk = keys_management::load_wallet(
        //     "your_password_he".as_bytes(),
        //     "./wallet.txt".to_string(),
        //     "your_password_he".as_bytes(),
        // )
        // .unwrap();

        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

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

        let position_side = relayer_types::PositionType::LONG;
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
        let order_message = create_trader_order_zkos(
            input_coin.clone(),
            output_memo.clone(),
            sk,
            scalar_hex.to_string(),
            232504500u64,
            "account_id".to_string(),
            position_side.to_str(),
            "MARKET".to_string(),
            20.0,
            232504500.0,
            232504500.0,
            "PENDING".to_string(),
            35000.0,
            35000.0,
        );
        println!("order_hex: {:?}", order_message);
        // println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }

    #[test]
    fn test_settle_trader_order_message() {
        dotenv::dotenv().expect("Failed loading dotenv");

        // get private key for the memo
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c24765b08a2ac4ce30a3e51ca1a3a16395c8c8499f0dc705275b2512ea78e216eb48f512e1db7d7b048a6827d43cad0e921517c22844b758bb518213e7b295c36a0fab02a";
        // get pk from client address
        let address = Address::from_hex(&client_address, address::AddressType::default()).unwrap();
        let client_pk: RistrettoPublicKey = address.into();

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
        dotenv::dotenv().expect("Failed loading dotenv");

        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

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
        dotenv::dotenv().expect("Failed loading dotenv");

        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

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
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

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
        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

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
}
