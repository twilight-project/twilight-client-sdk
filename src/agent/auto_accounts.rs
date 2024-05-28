use jsonrpc::client;
use rand::Rng;
use crate::relayer_rpcclient::method::{
    ByteRec, GetCreateTraderOrderResponse, GetTransactionHashResponse, TransactionHashArgs,
};
use crate::relayer_rpcclient::txrequest::{
    RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL,
};
use crate::relayer_types::CreateTraderOrderClientZkos;

use address::{Address, Network};
use curve25519_dalek::scalar::Scalar;
use jsonrpc_http_server::tokio::time::sleep;
use quisquislib::accounts::Account;
use quisquislib::elgamal::ElGamalCommitment;
use quisquislib::keys::{PublicKey, SecretKey};
use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
use rand::rngs::OsRng;
use std::time::Duration;
use transaction::vm_run::{Prover, Verifier};
use crate::transfer::TransferTxWallet;
use crate::zk_account::ZkAccount;
use zkvm::{program::Program, Commitment};
use zkvm::{
    zkos_types::{InputData, OutputCoin, OutputMemo, OutputState, Utxo},
    Input, Output,
};

use lazy_static::lazy_static;
use std::env;
use crate::relayer_types::CreateTraderOrderZkos;

pub fn load_accounts_to_db_from_main_account(
    sk: RistrettoSecretKey,
    sender_address: String,
    mut initial_balance: u64,
) {
    // create a loop ove main sender account and create multiple accounts
    // each iteration adds 7 accounts

    while initial_balance > 0 {
        println!("Initial Balance: {:?}", initial_balance);
        match create_db_accounts(sender_address.clone(), initial_balance, sk) {
            Ok(_) => {
                initial_balance -= 800;
                println!("Accounts created");
            }
            Err(e) => {
                println!("Error in creating accounts: {:?}", e);
            }
        };
    }
}

// created for testing tx_commit with multiple requests
fn test_tx_commit_rpc(sk: RistrettoSecretKey) {
    let coin_address = "0c042724dc1f37fc1157dcb234d45d035df66b1b62db7f445811dc3248ea981368b2f476e79bf8cd4922c3892184ed21486a94968b57a34c0cb59e68b8ad34910359036d0f".to_string();
    let value: u64 = 8821;
    println!("value: {:?}", value);
    self::create_boadcast_transfer_tx_single_account(coin_address.clone(), sk, value);

    let mut updated_sender_amount = value - 10;
    for i in 0..900 {
        println!("Iteration: {:?}", i);
        println!("Updated Sender Amount: {:?}", updated_sender_amount);
        let (_, upd_sender, _) =
            self::create_boadcast_transfer_tx_single_account(coin_address.clone(), sk, updated_sender_amount);
        updated_sender_amount = upd_sender;
    }
}

// creates a transfer tx for multiple reciever accounts
fn helper_multiple_account_transfer(
    sk: RistrettoSecretKey,
    sender_address: String,
    balance: u64,
) -> Result<TransferTxWallet, String> {
    let mut rng = rand::thread_rng();

    //get coin input from output
    let bob_input_1 =
        crate::chain::get_transaction_coin_input_from_address_fast(sender_address)?;

    let amount = 800u64;
    // get sender account from input
    let sender_account = bob_input_1.to_quisquis_account().unwrap();

    let updated_bob_balance = balance - amount;
    let (bob_pk, _) = sender_account.get_account();

    //create alice and fay account with 0 balance

    let alice_key = PublicKey::update_public_key(&bob_pk, Scalar::random(&mut rng));
    //let alice_address = address::Address::from(alice_key).as_hex();
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
    let (dave_account, dave_comm_rscalar) = Account::generate_account(
        PublicKey::update_public_key(&alice_key, Scalar::random(&mut rng)),
    );
    let (charlie_account, charlie_comm_rscalar) = Account::generate_account(
        PublicKey::update_public_key(&alice_key, Scalar::random(&mut rng)),
    );
    let (delta_account, delta_comm_rscalar) = Account::generate_account(
        PublicKey::update_public_key(&alice_key, Scalar::random(&mut rng)),
    );
    let (bravo_account, bravo_comm_rscalar) = Account::generate_account(
        PublicKey::update_public_key(&alice_key, Scalar::random(&mut rng)),
    );

    // create sender array
    let alice_reciever = transaction::Receiver::set_receiver(100, alice_account);
    let jay_reciever = transaction::Receiver::set_receiver(110, jay_account);
    let fay_reciever = transaction::Receiver::set_receiver(90, fay_account);
    let dave_reciever = transaction::Receiver::set_receiver(150, dave_account);
    let charlie_reciever = transaction::Receiver::set_receiver(130, charlie_account);
    let delta_reciever = transaction::Receiver::set_receiver(120, delta_account);
    let bravo_reciever = transaction::Receiver::set_receiver(100, bravo_account);

    let bob_sender = transaction::Sender::set_sender(
        -800,
        sender_account,
        vec![
            alice_reciever,
            jay_reciever,
            fay_reciever,
            dave_reciever,
            charlie_reciever,
            delta_reciever,
            bravo_reciever,
        ],
    );

    let tx_vector: Vec<transaction::Sender> = vec![bob_sender];
    let updated_balance_sender: Vec<u64> = vec![updated_bob_balance];
    let reciever_value_balance: Vec<u64> = vec![100, 110, 90, 150, 130, 120, 100];
    let commimment_scalar = vec![
        alice_comm_rscalar,
        jay_comm_rscalar,
        fay_comm_rscalar,
        dave_comm_rscalar,
        charlie_comm_rscalar,
        delta_comm_rscalar,
        bravo_comm_rscalar,
    ];
    let tx_wallet = crate::transfer::create_private_transfer_transaction_single_source_multiple_recievers(
            tx_vector,
            bob_input_1,
            sk,
            updated_balance_sender,
            reciever_value_balance.clone(),
            Some(&commimment_scalar),
            1u64,
        );
    // let updated_scalar = tx_wallet.get_encrypt_scalar().unwrap()[0];
    //  println!("comm_rscalar: {:?}", crate::util::scalar_to_hex(updated_scalar));
    Ok(tx_wallet)
}

// creates transfer tx for single account transfer
// creates a new account with random address to recieve the transfer
// returns the scalar, updated sender balance and receiver address
pub fn helper_single_transfer(
    coin_address: String,
    sk: RistrettoSecretKey,
    value: u64,
) -> (TransferTxWallet, u64, String) {
    // get pk from address_string
    let pk: RistrettoPublicKey =
        address::Address::from_hex(&coin_address, address::AddressType::Standard)
            .unwrap()
            .into();

    //get coin input from output
    let input =
        match crate::chain::get_transaction_coin_input_from_address_fast(coin_address){
            Ok(input) => input,
            Err(e) => panic!("Error in getting input: {:?}", e),
        };
    let amount = 10u64;
    let updated_sender_balance = value - amount;
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
        updated_sender_balance,
        1u64,
    );

    (tx_wallet, updated_sender_balance, new_address.clone())
}

// create seven accoounts from One main account
//add the created accounts to db
//
pub fn create_db_accounts(
    address: String,
    initial_balance: u64,
    sk: RistrettoSecretKey,
) -> Result<(), String> {
    //create Tx for multiple accounts transfer
    match helper_multiple_account_transfer(sk, address.clone(), initial_balance) {
        Ok(tx_wallet) => {
            // send the tx to chain
            let response: String = match crate::chain::tx_commit_broadcast_transaction(
                tx_wallet.get_tx(),
            ) {
                Ok(response) => response,
                Err(e) => return Err(e),
            };
            println!("response {:?}", response);
            let mut conn = crate::db_ops::establish_connection();
            let tx = tx_wallet.get_tx();
            let outputs = tx.get_tx_outputs();
            let is_on_chain = true;
            let encrypt_scalar = tx_wallet.get_encrypt_scalar().unwrap();
            // println!("Scalar length: {:?}", encrypt_scalar.len());
            let updated_balance: Vec<u64> = vec![100, 110, 90, 150, 130, 120, 100];
            // check for any of the reciever address. If one apperars then all have appear in the utxo set
            let reciever_address = outputs[1].as_output_data().get_owner_address().unwrap();

            //check for creation of new utxo
            for i in 0..10 {
                println!("Fetching utxo try {:?}", i);
                std::thread::sleep(Duration::from_secs(5));
                let utxo_id = crate::chain::get_utxo_id_by_address(
                    reciever_address.clone(),
                    zkvm::IOType::Coin,
                );
                if utxo_id.is_ok() {
                    // add the accounts to db
                    for i in 0..7 {
                        let scalar_str = crate::util::scalar_to_hex(encrypt_scalar[i]);
                        let balance = updated_balance[i];
                        let pk_address =
                            outputs[i + 1].as_output_data().get_owner_address().unwrap();
                        let _ = crate::db_ops::create_account(
                            &mut conn,
                            pk_address,
                            &scalar_str,
                            is_on_chain,
                            balance as i32,
                        );
                    }
                    break;
                }
            }
        }
        Err(e) => return Err(e),
    };

    Ok(())
}

// create and broadcast single transfer tx
// create a new receiver account
// return the scalar, updated sender balance and receiver address
pub fn create_boadcast_transfer_tx_single_account(
    coin_address: String,
    sk: RistrettoSecretKey,
    value: u64,
) -> (Scalar, u64, String) {
    let (tx_wallet, updated_sender_balance, reciever_address) =
        helper_single_transfer(coin_address, sk, value);
    // send the tx to chain
    let response =
        crate::chain::tx_commit_broadcast_transaction(tx_wallet.get_tx()).unwrap();
    println!("response {:?}", response);
    //check for creation of new utxo
    for i in 0..10 {
        std::thread::sleep(Duration::from_secs(3));
        let utxo_id_vec =
            crate::chain::get_coin_utxo_by_address_hex(reciever_address.clone())
                .unwrap();
        println!("Fetching utxo try {:?}", i);
        if utxo_id_vec.len() > 0 {
            println!("utxo_id_vec: {:?}", utxo_id_vec);
            break;
        }
    }
    (
        tx_wallet.get_encrypt_scalar().unwrap()[0].clone(),
        updated_sender_balance,
        reciever_address.clone(),
    )
}
