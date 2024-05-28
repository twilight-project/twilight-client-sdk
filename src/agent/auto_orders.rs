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
use zkvm::{program::Program, Commitment};
use zkvm::{
    zkos_types::{InputData, OutputCoin, OutputMemo, OutputState, Utxo},
    Input, Output,
};

use lazy_static::lazy_static;
use std::env;
use crate::relayer_types::CreateTraderOrderZkos;

pub fn place_market_trader_order(
    value: u64,
    sk: RistrettoSecretKey,
    client_address: String,
    rscalar: Scalar,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let input_coin = match crate::chain::get_transaction_coin_input_from_address_fast(
        client_address.to_string(),
    ) {
        Ok(input) => input,
        Err(e) => return Err(e),
    };

    // select a random value between 0 to 50
    let random_point = rand::thread_rng().gen_range(1, 50);
    let leverage = random_point as f64;
    let position_value = value * leverage as u64;
    let order_side_select = rand::thread_rng().gen_range(0, 2);

    let mut order_side = crate::relayer_types::PositionType::LONG;

    if order_side_select > 0 {
        order_side = crate::relayer_types::PositionType::SHORT;
    }
    let position_size = position_value * entry_price;
    let contract_path = "./relayerprogram.json";
    let programs =
        crate::programcontroller::ContractManager::import_program(&contract_path);

    let order_tx_message = crate::relayer::create_trader_order_zkos(
        input_coin,
        sk,
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
    ).map_err(|e| e.to_string())?;

    //send the msg to chain
    crate::relayer_types::CreateTraderOrderZkos::submit_order(
        order_tx_message.clone(),
    ) 
}


pub fn place_limit_trader_order(
    value: u64,
    sk: RistrettoSecretKey,
    client_address: String,
    rscalar: Scalar,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let input_coin = crate::chain::get_transaction_coin_input_from_address_fast(
        client_address.to_string(),
    )?;

    // select a random value between 0 to 50
    let random_point = rand::thread_rng().gen_range(1, 50);

    let leverage = random_point as f64;
    let position_value = value * leverage as u64;

    let random_price_variance = rand::thread_rng().gen_range(10, 500);

    let mut entry_price_local = entry_price - random_price_variance;
    let order_side_select = rand::thread_rng().gen_range(0, 2);

    let mut order_side = crate::relayer_types::PositionType::LONG;

    if order_side_select > 0 {
        order_side = crate::relayer_types::PositionType::SHORT;
        entry_price_local = entry_price + random_price_variance;
    }
    let position_size = position_value * entry_price_local;
    let contract_path = "./relayerprogram.json";
    let programs =
        crate::programcontroller::ContractManager::import_program(&contract_path);

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
        entry_price_local as f64,
        35000.0,
        position_value,
        position_size,
        order_side,
        &programs,
        0u32,
    ).map_err(|e|e.to_string())?;

    //     send the msg to chain
    crate::relayer_types::CreateTraderOrderZkos::submit_order(
        order_tx_message.clone())

}

pub fn create_order_and_add_to_db(sk:RistrettoSecretKey) -> Result<GetCreateTraderOrderResponse, String> {
       // get account from db
    let mut conn = crate::db_ops::establish_connection();
    let accounts = crate::db_ops::get_all_accounts(&mut conn).unwrap();
    let accountdb = accounts[0].clone();
    let btc_price = crate::relayer_rpcclient::txrequest::get_recent_price_from_relayer()?;
    let account_address = accountdb.pk_address.clone();
    let value = accountdb.balance as u64;
    let entry_price = btc_price.result.price as u64;
    let scalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
    let response  = place_market_trader_order(
        value,
        sk,
        account_address.clone(),
        scalar,
        entry_price,
    );
    println!("response: {:?}", response);
    if response.is_ok(){
        // get order details from exchange
        // create query to get order details
       
        let order_info: crate::relayer_rpcclient::method::GetTransactionHashResponse = crate::relayer_rpcclient::txrequest::get_order_details_transactiion_hashes(account_address)?;


        //add to order db
        let order_id = order_info.result[0].account_id.clone();
        let order_type: crate::relayer_types::OrderType = order_info.result[0].order_type.clone();
        let position_type = "LONG"; // could be anything for now
        let order_status = order_info.result[0].order_status.clone();

        let _ = crate::db_ops::create_order(
            &mut conn,
            &order_id,
            &order_type.to_str(),
            position_type,
            &order_status.to_str(),
            value as i64,
        );
    }
    response
}

fn helper_settle_order(sk: RistrettoSecretKey, account_address: String)-> Result<(), String>{
    
    // fetch order details
    
    let order_info: crate::relayer_rpcclient::method::GetTransactionHashResponse = crate::relayer_rpcclient::txrequest::get_order_details_transactiion_hashes(account_address.clone())?;
        // get Output to use in settlement
        let output = order_info.result[0].output.clone().unwrap();
        // get order infor from db
        let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
        let order = crate::db_ops::get_order_by_order_id(&account_address, &mut conn).unwrap();
   
       // create settlement reqest
       let settle_msg = crate::relayer::execute_order_zkos(output, &sk, account_id, uuid, order_type, settle_margin_settle_withdraw, order_status, execution_price_poolshare_price, tx_type);
        
       // println!("order_info: {:?}", order_info);
       Ok(())
    
}