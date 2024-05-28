use jsonrpc::client;
use rand::Rng;
use zkos_client_wallet::relayer_rpcclient::method::{
    ByteRec, GetCreateTraderOrderResponse, GetTransactionHashResponse, TransactionHashArgs,
};
use zkos_client_wallet::relayer_rpcclient::txrequest::{
    RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL,
};
use zkos_client_wallet::relayer_types::CreateTraderOrderClientZkos;

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
use zkos_client_wallet::transfer::TransferTxWallet;
use zkos_client_wallet::zk_account::ZkAccount;
use zkvm::{program::Program, Commitment};
use zkvm::{
    zkos_types::{InputData, OutputCoin, OutputMemo, OutputState, Utxo},
    Input, Output,
};

use lazy_static::lazy_static;
use std::env;
use zkos_client_wallet::relayer_types::CreateTraderOrderZkos;
use zkos_client_wallet::agent; // Add missing import statement

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

    // AHMAD TEST FUNCTION FOR ACCOUNTS
    //test_tx_commit_rpc(sk);
    let client_address = "0c50ce9927c331c653294d0f4f31faea7323855fe742bd5cb72105d11ebebe383db0058b2abb32745547ea815305e93d86c73c3bee9e79db1ffe413dec917332644ac29a0d";
    let initial_amount: u64 = 10000;

    //zkos_client_wallet::agent::auto_accounts::add_accounts_to_db(sk, client_address.to_string(), initial_amount);
          

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








// let mut receivers_vec: Vec<transaction::Receiver> = Vec::new();
// let mut remainivalue = 6000;

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
