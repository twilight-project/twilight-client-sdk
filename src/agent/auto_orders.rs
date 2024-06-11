use crate::relayer_rpcclient::method::GetCreateTraderOrderResponse;
use crate::relayer_types::OrderStatus;
use crate::relayer_types::PositionType;
use crate::relayer_types::TXType;
use rand::Rng;
// use jsonrpc_http_server::tokio::time::sleep;
use quisquislib::ristretto::RistrettoSecretKey;

use std::thread::sleep;
use std::time::Duration;

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

// Function to place a random Market order on the exchange
// creates the trade tx and broadcasts it to the chain
// adds the order to the db
pub fn place_random_market_trader_order(
    sk: RistrettoSecretKey,
    accountdb: crate::models::AccountDB,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let value = accountdb.balance as u64;
    let rscalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
    let coin_address = accountdb.pk_address;
    let input_coin =
        crate::chain::get_transaction_coin_input_from_address_fast(coin_address.clone())?;
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
    let response =
        crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone())?;

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
    )
    .map_err(|e| e.to_string())?;

    //delete account from db now. Account should be deleted in the calling function
    // let _ = crate::db_ops::delete_account_by_id(accountdb.id, &mut conn).map_err(|e|e.to_string())?;
    Ok(response)
}

// Function to place a random limit order on the exchange
// creates the trade tx and broadcasts it to the chain
// adds the order to the db
//
pub fn place_random_limit_trader_order(
    sk: RistrettoSecretKey,
    accountdb: crate::models::AccountDB,
    entry_price: u64,
) -> Result<GetCreateTraderOrderResponse, String> {
    //fetch input account from the address
    let value = accountdb.balance as u64;
    let rscalar = crate::util::hex_to_scalar(accountdb.scalar_str.unwrap()).unwrap();
    let coin_address = accountdb.pk_address;
    let input_coin =
        crate::chain::get_transaction_coin_input_from_address_fast(coin_address.clone())?;
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
    // println!("Order Tx Message: {:?}", order_tx_message);
    // send to chain
    let response =
        crate::relayer_types::CreateTraderOrderZkos::submit_order(order_tx_message.clone())?;
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
    )
    .map_err(|e| e.to_string())?;

    //delete account from db now. Account should be deleted in the calling function
    // let _ = crate::db_ops::delete_account_by_id(accountdb.id, &mut conn).map_err(|e|e.to_string())?;
    Ok(response)
}

// Autonomous function to place limit orders on exchange
//
pub fn limit_order_service(
    sk: RistrettoSecretKey,
    num_of_orders: i64,
    sleep_time: u64,
) -> Result<String, String> {
    println!("Starting Limit Order Service");
    // get a subset of 100 accounts that have their scalar available and are on chain
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let accounts =
        crate::db_ops::get_accounts_with_not_null_scalar_str(&mut conn, num_of_orders).unwrap();
    for acc in accounts.iter() {
        //get the latest price from the exchange
        let btc_price = crate::relayer_rpcclient::txrequest::get_recent_price_from_relayer()?;
        let entry_price = btc_price.result.price as u64;
        let response = place_random_limit_trader_order(sk, acc.clone(), entry_price);
        if response.is_ok() {
            // delete the account from db
            let _ = crate::db_ops::delete_account_by_id(acc.id, &mut conn)
                .map_err(|e| e.to_string())?;
            println!(
                "Order Placed Successfully for Account: {:?}",
                acc.pk_address
            );
        }
        let _ = sleep(Duration::from_secs(sleep_time));
    }

    Ok("Limit Orders Placed Successfully".to_string())
}

// Autonomous function to place Market orders on exchange
//
pub fn market_order_service(
    sk: RistrettoSecretKey,
    num_order: i64,
    sleep_time: u64,
) -> Result<String, String> {
    println!("Starting Market Order Service");
    // get a subset of 100 accounts that have their scalar available and are on chain
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let accounts =
        crate::db_ops::get_accounts_with_not_null_scalar_str_market(&mut conn, num_order).unwrap();
    for acc in accounts.iter() {
        //get the latest price from the exchange
        let btc_price = crate::relayer_rpcclient::txrequest::get_recent_price_from_relayer()?;
        let entry_price = btc_price.result.price as u64;
        let response = place_random_market_trader_order(sk, acc.clone(), entry_price);
        if response.is_ok() {
            // delete the account from db
            let _ = crate::db_ops::delete_account_by_id(acc.id, &mut conn)
                .map_err(|e| e.to_string())?;
            println!(
                "Order Placed Successfully for Account: {:?}",
                acc.pk_address
            );
        }
        let _ = sleep(Duration::from_secs(sleep_time));
    }

    Ok("Market Orders Placed Successfully".to_string())
}

// Autonomous service to settle Market orders
//
pub fn settle_market_orders_service(
    sk: RistrettoSecretKey,
    num_orders: i64,
    sleep_time: u64,
) -> Result<String, String> {
    println!("Starting Settle Market(FILLED) Orders Service");
    // get a list of all market orders
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    let orders = crate::db_ops::get_subset_order_by_status(&mut conn, "FILLED", num_orders)
        .map_err(|e| e.to_string())?;
    for order in orders.iter() {
        let response = single_settle_order_request(sk, order.clone());
        if response.is_ok() {
            println!("Order Settled Successfully");
            // delete the order from db
            let _ = crate::db_ops::delete_order_by_id(order.id, &mut conn)
                .map_err(|e| e.to_string())?;
            // add the account back to the db
            let _ = crate::db_ops::create_account(&mut conn, &order.order_id, None, true, 0 as i32);
        }
        match response {
            Ok(_) => {}
            Err(arg) => {
                if arg == "Order liquidated".to_string() {
                    println!("Order Liquidated ");
                    let _ = crate::db_ops::delete_order_by_id(order.id, &mut conn)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        let _ = sleep(Duration::from_secs(sleep_time));
    }
    Ok("Market Orders Settled Successfully".to_string())
}

// Autonomous service to Find Limit orders that have been Executed
//
pub fn find_executed_limit_orders_service(sk: RistrettoSecretKey) -> Result<String, String> {
    println!("Starting Find Executed Limit Orders Service");
    // get a list of all limit orders
    let mut conn: diesel::prelude::PgConnection = crate::db_ops::establish_connection();
    loop {
        let orders =
            crate::db_ops::get_orders_by_type(&mut conn, "LIMIT", 20).map_err(|e| e.to_string())?;
        let order_staus = crate::relayer_types::OrderStatus::FILLED;
        for order in orders.iter() {
            let address_hex = order.order_id.clone();
            // create zkos query to get the order details
            let query_msg = crate::relayer::query_trader_order_zkos(
                address_hex.clone(),
                &sk,
                address_hex.clone(),
                order.order_status.clone(),
            );

            // get the order details from the chain
            let order_info = crate::relayer_rpcclient::txrequest::get_trader_order_info(query_msg)?;
            // check if the order has been Filled
            // println!("order status : {:?}", order_info);
            if order_info.result.order_status == order_staus {
                // update the order status in the db
                let _ =
                    crate::db_ops::update_order_status_by_order_id(&mut conn, order.id, "FILLED")
                        .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok("Executed Limit Orders Found Successfully".to_string())
}
// Settle single order
// create a settlement request
// send the settlement request
//
pub fn single_settle_order_request(
    sk: RistrettoSecretKey,
    order: crate::models::OrderDB,
) -> Result<crate::relayer_rpcclient::method::GetExecuteTraderOrderResponse, String> {
    // fetch order details
    let order_address = order.order_id.clone();

    let order_info: crate::relayer_rpcclient::method::GetTransactionHashResponse =
        crate::relayer_rpcclient::txrequest::get_order_details_transactiion_hashes(
            order_address.clone(),
        )?;

    let result = order_info.result;
    if result.len() == 0 {
        return Err("No Order Found".to_string());
    }
    let mut output: Option<String> = None;
    // let mut liquidate = false;
    for hash in result.iter() {
        match hash.order_status {
            OrderStatus::LIQUIDATE => {
                // liquidate = true;
                return Err("Order liquidated".to_string());
            }
            OrderStatus::FILLED => {
                if hash.output.is_some() {
                    output = hash.output.clone();
                    // break;
                }
            }
            _ => {}
        }
    }
    if output.is_none() {
        return Err("No Output Found".to_string());
    }

    // convert hex string to Output
    let output = crate::util::hex_to_output(output.unwrap());
    let uuid_str = result[0].order_id.clone();
    let uuid = uuid::Uuid::parse_str(&uuid_str).unwrap();

    // create settlement reqest
    let settle_msg = crate::relayer::execute_order_zkos(
        output,
        &sk,
        order_address.clone(),
        uuid,
        "MARKET".to_string(),
        0.0,
        "FILLED".to_string(),
        0.0,
        TXType::ORDERTX,
    );
    // send settlement request
    crate::relayer_types::ExecuteTraderOrderZkos::submit_order(settle_msg.clone())
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
