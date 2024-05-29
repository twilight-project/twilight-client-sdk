use crate::relayer_rpcclient::method::{
    ByteRec, GetCreateTraderOrderResponse, GetTransactionHashResponse, TransactionHashArgs,
};
use crate::relayer_rpcclient::txrequest::{RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL};
use crate::relayer_types::{CreateTraderOrderClientZkos, TXType};
use crate::schema::orders::order_type;
use jsonrpc::client;
use rand::Rng;

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
use crate::relayer_types::{OrderType, PositionType};
use crate::relayer_types::CreateTraderOrderZkos;
use lazy_static::lazy_static;
use std::env;

fn helper_random_values() -> (f64, PositionType) {
   // select a random value between 0 to 50 for Leverage
    let random_point = rand::thread_rng().gen_range(1, 50);
    let leverage = random_point as f64;
    // select order side randomly
    let order_side_select = rand::thread_rng().gen_range(0, 2);
    let mut order_side = PositionType::LONG;
    if order_side_select > 0 {
        order_side = PositionType::SHORT;
    }
    (leverage, order_side)
}

pub fn place_random_market_trader_order(
    sk: RistrettoSecretKey,
    accountdb: crate::models::AccountDB,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let value = accountdb.balance as u64;
    let rscalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
    let coin_address = accountdb.pk_address;
    let input_coin = crate::chain::get_transaction_coin_input_from_address_fast(
        coin_address.clone(),
    )?;
    let (leverage, order_side) = helper_random_values();
    let position_value = value * leverage as u64;
    let position_size = position_value * entry_price;
    let contract_path = "./relayerprogram.json";
    let programs = crate::programcontroller::ContractManager::import_program(&contract_path);

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
        order_side.clone(),
        &programs,
        0u32,
    )
    .map_err(|e| e.to_string())?;
    // send to chain
    let response = crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone())?;
    
    //add to order db
    // create a db connection
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let order_status = "FILLED"; //Ignoring the order Status for now. Should be fetched from Tx Hashes

    let _ = crate::db_ops::create_order(
            &mut conn,
            &coin_address,
            "MARKET",
            &order_side.to_str(),
            order_status,
            value as i64,
    ).map_err(|e|e.to_string())?;

    //delete account from db now. Account should be deleted in the calling function 
   // let _ = crate::db_ops::delete_account_by_id(accountdb.id, &mut conn).map_err(|e|e.to_string())?;
    Ok(response)
}

pub fn place_random_limit_trader_order(
     sk: RistrettoSecretKey,
    accountdb: crate::models::AccountDB,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let value = accountdb.balance as u64;
    let rscalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
    let coin_address = accountdb.pk_address;
    let input_coin = crate::chain::get_transaction_coin_input_from_address_fast(
        coin_address.clone(),
    )?;
    let (leverage, order_side) = helper_random_values();

    let position_value = value * leverage as u64;

    let random_price_variance = rand::thread_rng().gen_range(10, 500);

    let entry_price_local = match order_side {
        PositionType::LONG => entry_price - random_price_variance,
        PositionType::SHORT => entry_price + random_price_variance,
    }; 
    let position_size = position_value * entry_price_local;
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
        entry_price_local as f64,
        35000.0,
        position_value,
        position_size,
        order_side.clone(),
        &programs,
        0u32,
    )
    .map_err(|e| e.to_string())?;
    // send to chain
    let response = crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone())?;
    // add the order to db
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let order_status = "PENDING"; //Ignoring the order Status for now. Should be fetched from Tx Hashes
    let _ = crate::db_ops::create_order(
            &mut conn,
            &coin_address,
            "LIMIT",
            &order_side.to_str(),
            order_status,
            value as i64,
    ).map_err(|e|e.to_string())?;

    //delete account from db now. Account should be deleted in the calling function 
   // let _ = crate::db_ops::delete_account_by_id(accountdb.id, &mut conn).map_err(|e|e.to_string())?;
    Ok(response)
}

// pub fn create_order_broadcast_and_add_to_db(
//     sk: RistrettoSecretKey,
//     accountdb: crate::models::AccountDB,
//     ord_type: crate::relayer_types::OrderType, // "LIMIT" or "MARKET"
// ) -> Result<GetCreateTraderOrderResponse, String> {
    
    
//     let btc_price = crate::relayer_rpcclient::txrequest::get_recent_price_from_relayer()?;
//     let value = accountdb.balance as u64;
//     let entry_price = btc_price.result.price as u64;
//     let scalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
//     let order_tx_message: String;

//     // create order based on order type
//     if ord_type == crate::relayer_types::OrderType::LIMIT {
//         order_tx_message = create_random_limit_trader_order(
//             value,
//             sk,
//             accountdb.pk_address.clone(),
//             scalar,
//             entry_price,
//         )?;
//     } else {
//         order_tx_message = create_random_market_trader_order(
//             value,
//             sk,
//             accountdb.pk_address.clone(),
//             scalar,
//             entry_price,
//         )?;
//     }

//     //send the order tx to the chain
//    let response =  crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone())?;
//     if response.is_ok() {
//         //add to order db
//         // create a db connection
//         let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
//         let position_type = "LONG"; // could be anything for now. NOT using it anywhere for search
//         let order_status = order_info.result[0].order_status.clone();

//         let _ = crate::db_ops::create_order(
//             &mut conn,
//             &order_id,
//             &order_type.to_str(),
//             position_type,
//             &order_status.to_str(),
//             value as i64,
//         );
//     }
//     response
// }

pub fn single_settle_order_add_coin_to_db(sk: RistrettoSecretKey, account_address: String) -> Result<crate::relayer_rpcclient::method::GetExecuteTraderOrderResponse, String> {
    // fetch order details

    let order_info: crate::relayer_rpcclient::method::GetTransactionHashResponse =
        crate::relayer_rpcclient::txrequest::get_order_details_transactiion_hashes(
            account_address.clone(),
        )?;
    // get Output to use in settlement
    let output = order_info.result[0].output.clone().unwrap();
    // convert hex string to Output
    let output =crate::util::hex_to_output(output);
    let uuid_str = order_info.result[0].order_id.clone();
    let uuid = uuid::Uuid::parse_str(&uuid_str).unwrap();

    // get order infor from db
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let _order = crate::db_ops::get_order_by_order_id(&account_address, &mut conn).unwrap();

    // create settlement reqest
    let settle_msg = crate::relayer::execute_order_zkos(
        output,
        &sk,
        account_address.clone(),
        uuid,
        "MARKET".to_string(),
        0.0,
        "PENDING".to_string(),
        0.0,
        TXType::ORDERTX,
    );

    // send settlement request
    let response = crate::relayer_types::ExecuteTraderOrderZkos::submit_order(settle_msg.clone());
    if response.is_ok() {
        // add this in accounts db. 
        // Check back after some time to see if the order has been settled
         let _ = crate::db_ops::create_account(
                            &mut conn,
                            &account_address,
                            None,
                            false,
                            0 as i32,
                        );
    }
    response
}



// add test for random values
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_values() {
        let (leverage, order_side) = helper_random_values();
        assert!(leverage > 0.0);
        assert!(leverage < 50.0);
        assert!(order_side == PositionType::LONG || order_side == PositionType::SHORT);
    }
}