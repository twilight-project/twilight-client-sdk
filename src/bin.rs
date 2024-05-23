
use rand::Rng;
use zkos_client_wallet::relayer_rpcclient::method::{ByteRec, GetCreateTraderOrderResponse, GetTransactionHashResponse, TransactionHashArgs};
use zkos_client_wallet::relayer_rpcclient::txrequest::{RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL};
use zkos_client_wallet::relayer_types::CreateTraderOrderClientZkos;

use zkos_client_wallet::transfer::TransferTxWallet;
use zkos_client_wallet::zk_account::ZkAccount;
use address::{Address, Network};
use curve25519_dalek::scalar::Scalar;
use jsonrpc_http_server::tokio::time::sleep;
use quisquislib::accounts::Account;
use quisquislib::elgamal::ElGamalCommitment;
use quisquislib::keys::{PublicKey, SecretKey};
use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use rand::rngs::OsRng;
use transaction::vm_run::{Prover, Verifier};
use zkvm::{program::Program, Commitment};
use std::time::Duration;
use zkvm::{
    zkos_types::{InputData, OutputCoin, OutputMemo, OutputState, Utxo},
    Input, Output,
};

use zkos_client_wallet::relayer_types::CreateTraderOrderZkos;
use lazy_static::lazy_static;
use std::env;

lazy_static! {
    pub static ref RELAYER_SEED_PHRASE: String = std::env::var("RELAYER_SEED_PHRASE")
        .expect("missing environment variable RELAYER_SEED_PHRASE");
}




fn main() {
    dotenv::dotenv().expect("Failed loading dotenv");
    
    
    println!("Hello, world!");
    //println!("LONG Order ");
    //println!("SHORT Order ");
  
    let sk = <RistrettoSecretKey as SecretKey>::from_bytes(RELAYER_SEED_PHRASE.as_bytes());
    
    let client_address = "0c54f1d02f24ad3a03f6bb43980470ce65ebe2d44b8b4ff61ca8a57631435e55239a4decbdb87af96b3e14ab46e3a53394fe16c209604ab30e5d3a43576704d600a20a1e24";
    let initial_amount: u64 = 694400;
    
    add_accounts_to_db(sk, client_address.to_string(), initial_amount);
//     let order_amount = 100u64;
    
//     let entry_price = helper_get_recent_price() as u64 + 80u64;
  
//     let (mut scalar, mut updated_sender_amount, mut address) =  helper_send_transfer_tx(client_address.to_string(), sk, initial_amount) ;
//      helper_place_limit_trader_order(order_amount, sk, address.to_string(), scalar, entry_price);
    
//     for i in 0..199{
//         println!("Iteration: {:?}", i);
//         let random_point = rand::thread_rng().gen_range(0, 300);
//         let entry_price = helper_get_recent_price() as u64 + random_point;
//         //entry_price = entry_price - 50;
//         println!("Updated Sender Amount: {:?}", updated_sender_amount);
//         (scalar, updated_sender_amount, address) =  helper_send_transfer_tx(client_address.to_string(), sk, updated_sender_amount);
//         //println!("scalar: {:?}, updated_balance: {:?}, address: {:?}", scalar, upd, address); 
//         helper_place_limit_trader_order(order_amount, sk, address.to_string(), scalar, entry_price);
        
//    }

    
  
    
   
}   

fn helper_place_limit_trader_order(value: u64, sk: RistrettoSecretKey, client_address: String, rscalar: Scalar, entry_price: u64)  {
    //fetch input account from the address
     let input_coin =
            zkos_client_wallet::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        // select a random value between 0 to 50
        let random_point = rand::thread_rng().gen_range(1, 50);
        let leverage = random_point as f64;
        let position_value = value * leverage as u64;
        //let mut entry_price = 67500u64;
       // let random_price = rand::thread_rng().gen_range(1, 1000);
        //entry_price = entry_price - random_price;
          //let random_point = rand::thread_rng().gen_range(0, 1);
        let mut order_side = zkos_client_wallet::relayer_types::PositionType::SHORT;
        //if random_point == 1 {
          //  order_side = zkos_client_wallet::relayer_types::PositionType::SHORT;
          //  entry_price = entry_price + random_price;
          //  println!("Short Order");
        //} 
        
        let position_size = position_value * entry_price;
        
      
        //let order_side = relayer_types::PositionType::LONG;
        
        let contract_path = "./relayerprogram.json";
        
        let programs = zkos_client_wallet::programcontroller::ContractManager::import_program(&contract_path);

  
        let order_tx_message = zkos_client_wallet::relayer::create_trader_order_zkos(
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
      // return order_tx_message;

    //    recreate trader order
    //  let client_order: CreateTraderOrderClientZkos = CreateTraderOrderClientZkos::decode_from_hex_string(order_tx_message.clone()).unwrap();
     //  let order_tx = client_order.tx;
    //    verify the transaction
     //  let verify_tx = order_tx.verify();
      // println!("verify_tx: {:?}", verify_tx);
   //     send the msg to chain
        let response = zkos_client_wallet::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone());
        println!("response: {:?}", response);
}
   


fn helper_multiple_account_transfer(sk: RistrettoSecretKey, sender_address: String, balance: u64)-> (TransferTxWallet, Vec<u64>, String) {
     let mut rng = rand::thread_rng();
        
        //get coin input from output 
        let bob_input_1 = zkos_client_wallet::chain::get_transaction_coin_input_from_address(sender_address).unwrap();
        let amount = 800u64;
        // get sender account from input
        let sender_account = bob_input_1.to_quisquis_account().unwrap();
        
        let updated_bob_balance = balance - amount;
        let (bob_pk, _) = sender_account.get_account();

        
        //create alice and fay account with 0 balance
        
        let alice_key = PublicKey::update_public_key(&bob_pk, Scalar::random(&mut rng));
        let alice_address = address::Address::from(alice_key).as_hex();
       // println!("Alice Address: {:?}", alice_address.clone());
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
    let alice_reciever = transaction::Receiver::set_receiver(100, alice_account);
    let jay_reciever = transaction::Receiver::set_receiver(110, jay_account);
    let fay_reciever = transaction::Receiver::set_receiver(90, fay_account);
    let dave_reciever = transaction::Receiver::set_receiver(150, dave_account);
    let charlie_reciever = transaction::Receiver::set_receiver(130, charlie_account);
    let delta_reciever = transaction::Receiver::set_receiver(120, delta_account);
    let bravo_reciever = transaction::Receiver::set_receiver(100, bravo_account);

    
    let bob_sender =
        transaction::Sender::set_sender(-800, sender_account, vec![alice_reciever, jay_reciever, fay_reciever, dave_reciever, charlie_reciever, delta_reciever, bravo_reciever]);
    
    let tx_vector:Vec<transaction::Sender> = vec![bob_sender];
    let updated_balance_sender: Vec<u64> = vec![updated_bob_balance];
    let reciever_value_balance: Vec<u64> = vec![100, 110, 90, 150, 130, 120, 100];
    let commimment_scalar = vec![alice_comm_rscalar, jay_comm_rscalar, fay_comm_rscalar, dave_comm_rscalar, charlie_comm_rscalar, delta_comm_rscalar, bravo_comm_rscalar];
        let tx_wallet = zkos_client_wallet::transfer::create_private_transfer_transaction_single_source_multiple_recievers(
            tx_vector,
            bob_input_1,
            sk,
            updated_balance_sender,
            reciever_value_balance.clone(),
            Some(&commimment_scalar),
            1u64,
        );
   // let updated_scalar = tx_wallet.get_encrypt_scalar().unwrap()[0];
   //  println!("comm_rscalar: {:?}", zkos_client_wallet::util::scalar_to_hex(updated_scalar));
        (tx_wallet, reciever_value_balance, alice_address.clone())
}

fn helper_single_transfer(coin_address: String, sk: RistrettoSecretKey, value: u64)-> (TransferTxWallet, u64, String){
    // get pk from address_string
        let pk : RistrettoPublicKey = address::Address::from_hex(&coin_address, address::AddressType::Standard).unwrap().into();
        
        //get coin input from output 
        let input = zkos_client_wallet::chain::get_transaction_coin_input_from_address(coin_address).unwrap();
        let amount = 100u64;
        let updated_sender_balance = value - amount;
        // update public key 
        let rscalar = Scalar::random(&mut OsRng);
        let updated_key = RistrettoPublicKey::update_public_key(&pk, rscalar);
        let new_address = address::Address::from(updated_key).as_hex();
        // create Single Private Transfer Transaction
        let tx_wallet = zkos_client_wallet::transfer::create_private_transfer_tx_single(
            sk.clone(),
            input,
            new_address.clone(),
            amount,
            false,
            updated_sender_balance,
            1u64,
        );
        
        (tx_wallet, updated_sender_balance, new_address.clone())
}

fn create_db_accounts(address: String, initial_balance: u64, sk: RistrettoSecretKey) {
    
    let (tx_wallet, updated_balance, reciever_address) = helper_multiple_account_transfer(sk,  address, initial_balance);
    // send the tx to chain
    let response = match zkos_client_wallet::chain::tx_commit_broadcast_transaction(tx_wallet.get_tx()){
        Ok(response) => response,
        Err(arg) => arg,  
    };
   // println!("response {:?}", response);
    //check for creation of new utxo
    for i in 0..10{
       std::thread::sleep(Duration::from_secs(5));
        let utxo_id_vec = zkos_client_wallet::chain::get_coin_utxo_by_address_hex(reciever_address.clone()).unwrap();
       //println!("Fetching utxo try {:?}", i);
        if utxo_id_vec.len() > 0 {
            // add the accounts to db
            let mut conn = zkos_client_wallet::db_ops::establish_connection();
            let tx = tx_wallet.get_tx();
            let outputs = tx.get_tx_outputs();
            let is_on_chain = true;
            let encrypt_scalar = tx_wallet.get_encrypt_scalar().unwrap();
           // println!("Scalar length: {:?}", encrypt_scalar.len());
            
            for i in 0..7 {
                let scalar_str = zkos_client_wallet::util::scalar_to_hex(encrypt_scalar[i]);
                let balance = updated_balance[i];
                let pk_address = outputs[i+1].as_output_data().get_owner_address().unwrap();
                zkos_client_wallet::db_ops::create_account(&mut conn, pk_address, &scalar_str, is_on_chain, balance as i32).unwrap();
            }
            break;
        }
    }
    

} 

    



fn helper_send_transfer_tx(coin_address: String, sk:RistrettoSecretKey, value: u64) -> (Scalar, u64, String) {
    let (tx_wallet, updated_sender_balance, reciever_address) = helper_single_transfer(coin_address, sk, value);
    // verify the tx
  //  let verified = tx_wallet.get_tx().verify();
  //  println!("Verified: {:?}", verified);
    // send the tx to chain
    let response = zkos_client_wallet::chain::tx_commit_broadcast_transaction(tx_wallet.get_tx()).unwrap();
    println!("response {:?}", response);
   // println!("Scalar Wallet{:?}", tx_wallet.get_encrypt_scalar().unwrap()[0].clone());
    println!("reciever_address: {:?}", reciever_address.clone());
    //check for creation of new utxo
    
    for i in 0..10{
       std::thread::sleep(Duration::from_secs(8));
        let utxo_id_vec = zkos_client_wallet::chain::get_coin_utxo_by_address_hex(reciever_address.clone()).unwrap();
       println!("Fetching utxo try {:?}", i);
        if utxo_id_vec.len() > 0 {
             println!("utxo_id_vec: {:?}", utxo_id_vec);
            break;
        }

    } 
    (tx_wallet.get_encrypt_scalar().unwrap()[0].clone(), updated_sender_balance, reciever_address.clone())
            
}

fn helper_get_recent_price()-> f64 {
     let tx_send: RpcBody<Option<String>> = RpcRequest::new(
            None,
            zkos_client_wallet::relayer_rpcclient::method::Method::btc_usd_price,
        );
        let res: Result<
            zkos_client_wallet::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
> = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match zkos_client_wallet::relayer_rpcclient::method::GetBTCPRice::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

       // println!("order response : {:#?}", response_unwrap);
        // get price 
        response_unwrap.unwrap().result.price
        
}

fn helper_fetch_order_details_transactiion_hashes(address: String)-> Result<GetTransactionHashResponse, String>{
    let tx_hash_arg1 = TransactionHashArgs::AccountId {
            id: address,
            status: None,
        };
        let tx_request: RpcBody<TransactionHashArgs> = RpcRequest::new(
            tx_hash_arg1,
            zkos_client_wallet::relayer_rpcclient::method::Method::transaction_hashes,
        );
        let res: Result<
            zkos_client_wallet::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_request.send(PUBLIC_API_RPC_SERVER_URL.clone());

        match res {
            Ok(rpc_response) => match GetTransactionHashResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        }        
}

fn helper_query_trader_order_info(msg: String) -> Result<zkos_client_wallet::relayer_rpcclient::method::GetTraderOrderInfoResponse, String> {
    let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: msg },
            zkos_client_wallet::relayer_rpcclient::method::Method::trader_order_info,
        );
        let res: Result<
            zkos_client_wallet::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        match res {
            Ok(rpc_response) => match zkos_client_wallet::relayer_rpcclient::method::GetTraderOrderInfoResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        }

}
fn helper_settle_order(){

}
fn add_accounts_to_db(sk: RistrettoSecretKey, sender_address: String,  mut initial_balance: u64) {

    // create a loop ove main sender account and create multiple accounts
    // each iteration adds 7 accounts 
    
    while initial_balance > 0  
    {
        println!("Initial Balance: {:?}", initial_balance);
        create_db_accounts(sender_address.clone(), initial_balance, sk);
        initial_balance -= 800;
    }
}





// let mut receivers_vec: Vec<transaction::Receiver> = Vec::new();
    // let mut remaining_value = 6000;

    // while remaining_value > 0 {
    //     let value = rand::thread_rng().gen_range(1..=remaining_value);
    //     let (receiver_account, random_scalars) = Account::generate_random_account_with_value(value.into());
    //     let receiver = transaction::Receiver::set_receiver(value, receiver_account);
    //     receivers_vec.push(receiver);
    //     remaining_value -= value;
    // }
    // let mut sender_values: Vec<i64> = Vec::new();
    
    // let target_sum = 6000;
    // let num_elements = 7;

    // let mut vector = vec![0; num_elements];

    // Generate 6 random numbers and fill the first 6 elements of the vector
    // let mut sum = 0;
    // for i in 0..num_elements - 1 {
    //     let high = target_sum - sum;
    //     let value = rng.gen_range(10,&high) as i32;
    //     vector[i] = value;
    //     sum += value;
    // }

    // The last element is the difference to reach the target_sum
//     vector[num_elements - 1] = target_sum - sum;

//     println!("Generated vector: {:?}", vector);
//    println!("Sum of vector: {}", vector.iter().sum::<i32>());
    
  //  println!("Range values: {:?}", range_values);
    // for _ in 0..6 {
    //     let index = rand::thread_rng().gen_range(0..range_values.len());
    //     let value = range_values[index];
    //     sender_values.push(value);
    //     remaining_sum -= value;
    //     range_values.remove(index);
    // }
   // sender_values.push(remaining_sum);
    //println!("Sender values: {:?}", sender_values);