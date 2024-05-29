
const TEST_SEED: &str =
    "f8i2eBnltoHtPg9TBtIlzcsqQV+sDkaLfIjLXFPIALUx//qZlCrY1AWJbqSLLzL1wVau9IerWXHFKFK300XiIg==";

const RELAYER_SEED: &str =
   "LPf7DBZSdlKYSk7i0qfB+V0dKw7Ul6NxcbuPufKPuUFj/mV0KJL+w1GTUlzHG6vyM1LLEuN+yaPyddveiUC+ag=="; 

   //8vKfd6kCrttU4n17u5OKUVbJqIXyCqZc/9f7t8a8tEJwm0ATbL96mtPjW79f6cH/8FtF/KrjeMKUfndchD74tg==
   //8vKfd6kCrttU4n17u5OKUVbJqIXyCqZc/9f7t8a8tEJwm0ATbL96mtPjW79f6cH/8FtF/KrjeMKUfndchD74tg==

   //LPf7DBZSdlKYSk7i0qfB+V0dKw7Ul6NxcbuPufKPuUFj/mV0KJL+w1GTUlzHG6vyM1LLEuN+yaPyddveiUC+ag==
   //LPf7DBZSdlKYSk7i0qfB+V0dKw7Ul6NxcbuPufKPuUFj/mV0KJL+w1GTUlzHG6vyM1LLEuN+yaPyddveiUC+ag==
#[cfg(test)]
mod tests {
    use crate::relayer_rpcclient::method::{GetTransactionHashResponse, TransactionHashArgs};
    use crate::relayer_rpcclient::txrequest::{RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL};
    use crate::test::{TEST_SEED, RELAYER_SEED};
    use crate::*;
    use crate::zk_account::ZkAccount;
    use address::Network;
    use curve25519_dalek::scalar::Scalar;
    use quisquislib::accounts::Account;
    use quisquislib::elgamal::ElGamalCommitment;
    use quisquislib::keys::{PublicKey, SecretKey};
    use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
    use rand::rngs::OsRng;
    
use std::time::Duration;
    use zkvm::{
        zkos_types::Utxo,
        Input, Output,
    };

    #[test]
    fn test_keypair_verification() {
        let sk = <RistrettoSecretKey as quisquislib::keys::SecretKey>::from_bytes(RELAYER_SEED.as_bytes());
        
        println!("sk {:?}", sk);
        // Load chain Metadata
        dotenv::dotenv().expect("Failed loading dotenv");

        let coin_address: String = "0c3023e2e4de3790b6f632086916d96bc4cf72c57e5e490567c09bcd24e7561547c0bf4e2050597b3bc097bd3e2100eb29e4407cdbc1a043cc92e255e5eadf026df814f9a6".to_string();
    
        // //get coin output from chain    
        let utxo_id_vec = crate::chain::get_coin_utxo_by_address_hex(coin_address).unwrap();
        println!("utxo_id {:?}", utxo_id_vec[0]);
        // // get output 
        let coin_output = crate::chain::get_coin_output_by_utxo_id_hex(utxo_id_vec[0].clone()).unwrap();
         println!("coin_output {:?}", coin_output);
        // // create zk_account from OutputCoin
         let account: ZkAccount = ZkAccount::from(coin_output.clone());
         let result = account.verify_keypair(&sk);
         println!("result {:?}", result);
         let acc_str = account.to_hex_str();
         let decrypt = zk_account::decrypt_zk_account_value(RELAYER_SEED, acc_str).unwrap();
         println!("result {:?}", decrypt);
        // println!("zk_account {:?}", account);
        //assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_transfer_account_scalar(){
         // Load chain Metadata
        dotenv::dotenv().expect("Failed loading dotenv");

        //let sk = <RistrettoSecretKey as quisquislib::keys::SecretKey>::from_bytes(RELAYER_SEED.as_bytes());
        let coin_address: String = "0c0410d7b8466a3e9854d7871b2db29129491cae520cbcc40511b6d809f2e1da2a520239dbca83672626cba9de150fdc8ae684646dcb610460fe827f7136dbb4535cf40b5b".to_string();
       // let coin_address_old = "0cd85b2d47c51347dab3464eb844f50492e511a8fd307e2111877caf3567286473d8c4764f1c8abf8fc3b857355173635e16547f19c11bb9f902962d961720eb514e422da6";
        // get pk from address_string
        let pk : RistrettoPublicKey = address::Address::from_hex(&coin_address, address::AddressType::Standard).unwrap().into();
        
        // //get coin output from chain    
        let utxo_id_vec = crate::chain::get_coin_utxo_by_address_hex(coin_address).unwrap();
         // // get output 
        let coin_output = crate::chain::get_coin_output_by_utxo_id_hex(utxo_id_vec[0].clone()).unwrap();
        // get Account from Output
        let account : Account = Output::to_quisquis_account(&coin_output).unwrap();
        let amount = 1233u64;
        let _commitment_scalar_hex: &str =
            "785c75ead6cea37bcebe13654be574151077a398e73c64a393f65a5e667efa04";
        // let encryption_commitment_scalar =
        //     crate::util::hex_to_scalar(commitment_scalar_hex.to_string()).unwrap();
        let bytes:[u8;32] = [173, 247, 181, 254, 22, 93, 68, 194, 234, 210, 165, 132, 45, 134, 236, 90, 255, 120, 236, 55, 33, 184, 126, 154, 23, 105, 254, 168, 81, 113, 10, 10];
        let encryption_commitment_scalar = Scalar::from_canonical_bytes(bytes).unwrap();

        // recreate encryption with scalar and balance
        let encrypt_new = ElGamalCommitment::generate_commitment(&pk, encryption_commitment_scalar, Scalar::from(amount));
        // get output encryption
        let (pk_old, enc_old) = account.get_account();
        // compare pk
        assert_eq!(pk, pk_old);
        // compare enc
        assert_eq!(encrypt_new, enc_old);    

    }

    #[test]
    fn test_db_account_scalar_verification(){
        // Load chain Metadata
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        // get all accounts
        //let pk_address = "0cf47a707ab3f2896f5b710597ec53378bd330487cb4641bc11f34652816966c6d2086d468393fbd05cfce950c772581363a70fc49829c30aef5fee125b3e36b7254b71645";
        //let account_db = crate::db_ops::get_account_by_pk_address(pk_address, &mut conn).unwrap();
        
        let accounts = crate::db_ops::get_all_accounts(&mut conn).unwrap();
        //println!("accountDB {:?}", account_db.clone());
        for account_db in accounts.iter(){
            let pk_address = account_db.pk_address.clone();
            let scalar_hex = account_db.scalar_str.clone().unwrap();
            let scalar = crate::util::hex_to_scalar(scalar_hex).unwrap();
            let balance = account_db.balance as u64;
            //println!("balance {:?}", balance);
            // get Account from Output
            let utxo_id_vec = crate::chain::get_coin_utxo_by_address_hex(pk_address.to_string()).unwrap();
            let coin_output = crate::chain::get_coin_output_by_utxo_id_hex(utxo_id_vec[0].clone()).unwrap();
            let account : Account = Output::to_quisquis_account(&coin_output).unwrap();
            let (pk_old, enc_old) = account.get_account();
            let encrypt_new = ElGamalCommitment::generate_commitment(&pk_old, scalar, Scalar::from(balance));
            // compare enc
            assert_eq!(encrypt_new, enc_old);
        }
        // let scalar_hex = account_db.scalar_str.unwrap();
        // let scalar = crate::util::hex_to_scalar(scalar_hex).unwrap();
        // let balance = account_db.balance as u64;
        // //println!("balance {:?}", balance);
        // // get Account from Output
        // let utxo_id_vec = crate::chain::get_coin_utxo_by_address_hex(pk_address.to_string()).unwrap();
        // let coin_output = crate::chain::get_coin_output_by_utxo_id_hex(utxo_id_vec[0].clone()).unwrap();
        // let account : Account = Output::to_quisquis_account(&coin_output).unwrap();
        // let (pk_old, enc_old) = account.get_account();
        // let encrypt_new = ElGamalCommitment::generate_commitment(&pk_old, scalar, Scalar::from(balance));
        // // compare enc
        // assert_eq!(encrypt_new, enc_old);
        
    }
    #[test]
    fn test_transfer_private_single(){
        // Load chain Metadata
        dotenv::dotenv().expect("Failed loading dotenv");

        let sk = <RistrettoSecretKey as quisquislib::keys::SecretKey>::from_bytes(RELAYER_SEED.as_bytes());
        let coin_address: String = "0cf05ad3645017dde85fc2efea413ed83251541817b4da34a953ac8fe1b56f5e3f401ede9e1a83033c5082c5bbdce2bcc0f21ef70b56dbd74f13c5cf9b7009ed11f18eaea3".to_string();
        // get pk from address_string
        let pk : RistrettoPublicKey = address::Address::from_hex(&coin_address, address::AddressType::Standard).unwrap().into();
        
        //get coin input from output 
        let input = crate::chain::get_transaction_coin_input_from_address(coin_address).unwrap();
        
        let amount = 1233u64;
        // update public key 
        let rscalar = Scalar::random(&mut OsRng);
        let updated_key = RistrettoPublicKey::update_public_key(&pk, rscalar);
        let new_address = address::Address::from(updated_key).as_hex();
        // create Single Private Transfer Transaction
        let tx_wallet = crate::transfer::create_private_transfer_tx_single(
            sk.clone(),
            input,
            new_address.clone(),
            amount,
            false,
            0u64,
            1u64,
        );
        println!("tx_wallet {:?}", tx_wallet.get_tx());
        //println!("Scalar Wallet{:?}", tx_wallet.get_encrypt_scalar());

        // send the tx to chain
        let response = crate::chain::tx_commit_broadcast_transaction(tx_wallet.get_tx()).unwrap();
        println!("response {:?}", response);
        
        // sleep for 2 seconds to let the utxo set update
        std::thread::sleep(Duration::from_secs(2));
        let commitment_scalar = tx_wallet.get_encrypt_scalar().unwrap()[0].clone() ;
        println!("Scalar Wallet{:?}", commitment_scalar.clone());
        
        // //get coin output from chain    
        let utxo_id_vec = crate::chain::get_coin_utxo_by_address_hex(new_address).unwrap();
        // // get output 
        let coin_output = crate::chain::get_coin_output_by_utxo_id_hex(utxo_id_vec[0].clone()).unwrap();
        
        // get Account from Output
        let account: Account = Output::to_quisquis_account(&coin_output).unwrap();
        // get output encryption
        let (pk_old, enc_old) = account.get_account();
        // recreate encryption with scalar and balance
        let encrypt_new = ElGamalCommitment::generate_commitment(&pk_old, commitment_scalar, Scalar::from(amount));
        
        // compare enc
        assert_eq!(encrypt_new, enc_old);    



    }

    #[test]
    fn convert_bytes_to_hex(){
        let bytes = [77, 248, 36, 68, 30, 218, 138, 123, 106, 210, 26, 141, 28, 98, 78, 29, 101, 134, 227, 150, 204, 70, 107, 172, 83, 59, 127, 181, 38, 52, 56, 8];
        let hex = hex::encode(bytes);
        println!("hex {:?}", hex);
    }
// let coin_address: String = "0c4ebfaffc5587295c6b63f2ccecefd85ab72d0ef3caae13bceb40400f07056537844728a12de100bde2987cfdc474569f5436cdf9ac3fc0f0b8d8449df7fee36958463d3b".to_string();
    #[test]
    fn test_tranfer_multiple_scalar()
    {
        let mut rng = rand::thread_rng();
        // Bob transfers 5000 to alice (1000), faye(2000), jay(1500) and dave(500)
        let (bob_account_1, bob_sk_account_1) =
        Account::generate_random_account_with_value(6300u64.into());


        //Create sender updated account vector for the verification of sk and bl-v
        let sender_bob = 5000 - 5000; //bl-v
    
        // create input from account vector
        let bob_utxo = Utxo::random(); //Simulating a valid UTXO input
        let bob_input_1 =
            Input::input_from_quisquis_account(&bob_account_1, bob_utxo, 0, Network::default());
        
        let (bob_pk, _) = bob_account_1.get_account();
        //create alice and fay account with 0 balance
        
        let alice_key = PublicKey::update_public_key(&bob_pk, Scalar::random(&mut rng));

        let (alice_account, alice_comm_rscalar) = Account::generate_account(alice_key.clone());
        
        let (fay_account, fay_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));
        let (jay_account, jay_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));
    let (dave_account, dave_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));
     let (charlie_account, charlie_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));
     let (delta_account, delta_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));
     let (bravo_account, bravo_comm_rscalar) = Account::generate_account(PublicKey::update_public_key(
        &alice_key,
        Scalar::random(&mut rng),
    ));

    // create sender array
    let alice_reciever = transaction::Receiver::set_receiver(1000, alice_account);
    let fay_reciever = transaction::Receiver::set_receiver(2000, fay_account);
    let jay_reciever = transaction::Receiver::set_receiver(1500, jay_account);
    let dave_reciever = transaction::Receiver::set_receiver(500, dave_account);
    let charlie_reciever = transaction::Receiver::set_receiver(600, charlie_account);
    let delta_reciever = transaction::Receiver::set_receiver(400, delta_account);
    let bravo_reciever = transaction::Receiver::set_receiver(300, bravo_account);

    
    let bob_sender =
        transaction::Sender::set_sender(-6300, bob_account_1, vec![alice_reciever, jay_reciever, fay_reciever, dave_reciever, charlie_reciever, delta_reciever, bravo_reciever]);
    
    let tx_vector:Vec<transaction::Sender> = vec![bob_sender];
    let updated_balance_sender: Vec<u64> = vec![sender_bob];
    let reciever_value_balance: Vec<u64> = vec![1000, 1500, 2000, 500, 600, 400, 300];
    let commimment_scalar = vec![alice_comm_rscalar, jay_comm_rscalar, fay_comm_rscalar, dave_comm_rscalar, charlie_comm_rscalar, delta_comm_rscalar, bravo_comm_rscalar];
        let tx_wallet = crate::transfer::create_private_transfer_transaction_single_source_multiple_recievers(
            tx_vector,
            bob_input_1,
            bob_sk_account_1,
            updated_balance_sender,
            reciever_value_balance,
            Some(&commimment_scalar),
            1u64,
        );
        
        let tx = tx_wallet.get_tx();
        // verify the tx
        let proof = tx.verify().unwrap();
        println!("proof {:?}", proof);


    }
// lazy_static! {
//     pub static ref RELAYER_RPC_SERVER_URL: String = std::env::var("RELAYER_RPC_SERVER_URL")
//         .expect("missing environment variable RELAYER_RPC_SERVER_URL");
// }

    #[test]
    pub fn test_create_trader_order_client_tx() {
        dotenv::dotenv().expect("Failed loading dotenv");

        //derive private key;
        let sk = <RistrettoSecretKey as SecretKey>::from_bytes(RELAYER_SEED.as_bytes());
        println!("sk {:?}", sk);
        let client_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b70cd8f694dc";
        let value: u64 = 1400u64;
        let input_coin =
            crate::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        let scalar_hex = "8e09a846788e21f9a1b22ba245fdae8df85e9d651fd720ab2274dbf034e4cc08";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
       
        
        let leverage = 15.0;
        let position_value = value * leverage as u64;
          let entry_price = 60500u64;
        let position_size = position_value * entry_price;
        let order_side = relayer_types::PositionType::LONG;
        let contract_path = "./relayerprogram.json";
        
        let programs = crate::programcontroller::ContractManager::import_program(&contract_path);

  
        let order_tx_message = crate::relayer::create_trader_order_zkos(
            input_coin,
            sk,
            rscalar,
            value,
            order_side.to_str(),
            "LIMIT".to_string(),
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
        ).unwrap();
       println!("order_hex: {:?}", order_tx_message.clone());

       // recreate trader order
       //let client_order: CreateTraderOrderClientZkos = CreateTraderOrderClientZkos::decode_from_hex_string(order_tx_message).unwrap();
       // let order_tx = client_order.tx;
        // verify the transaction
       // let verify_tx = order_tx.verify();
       // println!("verify_tx: {:?}", verify_tx);
        //send the msg to chain
       // let response = crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone());
       // println!("response: {:?}", response);
}

    #[test]
    fn test_transaction_hashes_response(){
        dotenv::dotenv().expect("Failed loading dotenv");

        let tx_hash_arg1 = TransactionHashArgs::AccountId {
            id: "0cd2be3c0d8ef4fdeaa60f25a3bb051e856486f5ce7db4b1f16506150875e8af32bcf1a2fe5ee9da9baa3b58ae7e1b99756711db9ea1cc2774fee9a8cbceef270e6762facf".to_string(),
            status: None,
        };
        // let _tx_hash_arg2 = TransactionHashArgs::RequestId {
        //     id: "REQIDAEF51D3147D9FD400135A13DE7ADE176F171597F2D37936C0129BB11F05B6B68".to_string(),
        //     status: None,
        // };
        let tx_send: RpcBody<TransactionHashArgs> = RpcRequest::new(
            tx_hash_arg1,
            crate::relayer_rpcclient::method::Method::transaction_hashes,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetTransactionHashResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
    }
    #[test]
    fn test_create_account_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let pk_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b70cd8f694dc";
        let scalar_str = "8e09a846788e21f9a1b22ba245fdae8df85e9d651fd720ab2274dbf034e4cc08";
        let is_on_chain = false;
        let balance = 1000;
        let account = crate::db_ops::create_account(&mut conn, pk_address, Some(scalar_str), is_on_chain, balance).unwrap();
        println!("account {:?}", account);
    }
    #[test]
    fn test_get_all_accounts_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let accounts = crate::db_ops::get_all_accounts(&mut conn).unwrap();
        
        //println!("accounts {:?}", accounts);
        print!("Number of accounts {:?}", accounts.len());
    }
    #[test]
    fn test_get_account_by_pk_address_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let pk_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b70cd8f694dc";
        let account = crate::db_ops::get_account_by_pk_address(pk_address, &mut conn).unwrap();
        println!("account {:?}", account);
    }
    #[test]
    fn test_delete_account_by_id_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let id = 1;
        let size = crate::db_ops::delete_account_by_id(id, &mut conn).unwrap();
        println!("size {:?}", size);
    }
    #[test]
    fn test_delete_all_accounts_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let size = crate::db_ops::delete_all_accounts(&mut conn).unwrap();
        println!("size {:?}", size);
    }
    #[test]
    fn delete_last_100_entries_accounts(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut _count = 6089;
        // for _i in 0..100{
        //     count += 1;
        // }
        // let mut conn = crate::db_ops::establish_connection();
        // let size = crate::db_ops::delete_account_by_id(count, &mut conn).unwrap();
       // println!("size {:?}", size);
    }
    #[test]
       fn test_create_null_string_account_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let pk_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b70cd8f694dc";
        let scalar_str = None;
        let is_on_chain = false;
        let balance = 0;
        let account = crate::db_ops::create_account(&mut conn, pk_address, scalar_str, is_on_chain, balance).unwrap();
        println!("account {:?}", account);
        // get account id
        let id = account.id;
        // get account by id
        let account_id = crate::db_ops::get_account_by_id(id, &mut conn).unwrap();
        println!("fetched from DB account_id {:?}", account_id);
        // delete the account by id
        let size = crate::db_ops::delete_account_by_id(id, &mut conn).unwrap();
        println!("deleted account size {:?}", size);
    }

    #[test]
    fn test_get_accounts_with_null_scalar_str_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let accounts = crate::db_ops::get_accounts_with_null_scalar_str(&mut conn).unwrap();
        
        println!("accounts {:?}", accounts);
        print!("Number of accounts {:?}", accounts.len());
    }
    #[test]
    fn create_account_with_null_str_db()
    {
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        for _i in 0..5{
        let pk_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b80cd8e694dd";
        let scalar_str = None;
        let is_on_chain = false;
        let balance = 0;
        let _account = crate::db_ops::create_account(&mut conn, pk_address, scalar_str, is_on_chain, balance).unwrap();
        }
        //println!("account {:?}", account);
    }
     #[test]
    fn test_get_accounts_with_scalar_str_db(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let accounts = crate::db_ops::get_all_accounts_with_not_null_scalar_str(&mut conn).unwrap();
        let account_subset = crate::db_ops::get_accounts_with_not_null_scalar_str(&mut conn, 15).unwrap();
        println!("accounts {:?}", account_subset);
        print!("Number of accounts {:?}", accounts.len());
        print!("Number of accounts {:?}", account_subset.len());
    }
    #[test]
    fn test_delete_account_by_address(){
        dotenv::dotenv().expect("Failed loading dotenv");
        let mut conn = crate::db_ops::establish_connection();
        let pk_address = "0c1473fc6e097057d678c9c5cfa886e084bc2a425671200bc6d931d682c1623a6d7e6fb5a6381c7cef4b42875655b5aa78141f2dda25ea2f7585e0ca2b4402b80cd8e694dd";
        let size = crate::db_ops::delete_account_by_pk_address(pk_address, &mut conn).unwrap();
        println!("size {:?}", size);
    }
}