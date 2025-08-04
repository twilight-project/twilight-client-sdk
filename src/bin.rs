#![allow(unused_imports)]
#![allow(dead_code)]
use lazy_static::lazy_static;
use quisquislib::keys::SecretKey;
use quisquislib::ristretto::RistrettoSecretKey;
use std::{
    thread::{self, sleep},
    time::Duration,
};
use twilight_client_sdk::agent::auto_accounts::get_account_balance;
lazy_static! {
    pub static ref RELAYER_SEED_PHRASE: String = std::env::var("RELAYER_SEED_PHRASE")
        .expect("missing environment variable RELAYER_SEED_PHRASE");
    pub static ref ACCOUNT_1: String =
        std::env::var("ACCOUNT_1").expect("missing environment variable ACCOUNT_1");
    pub static ref ACCOUNT_2: String =
        std::env::var("ACCOUNT_2").expect("missing environment variable ACCOUNT_2");
    pub static ref ACCOUNT_1_BALANCE: String =
        std::env::var("ACCOUNT_1_BALANCE").unwrap_or_else(|_| "0".to_string());
    pub static ref ACCOUNT_2_BALANCE: String =
        std::env::var("ACCOUNT_2_BALANCE").unwrap_or_else(|_| "0".to_string());
}

fn main() {
    dotenvy::dotenv().expect("Failed loading dotenv");
    let sk = <RistrettoSecretKey as SecretKey>::from_bytes(RELAYER_SEED_PHRASE.as_bytes());

    let create_db_accounts1 = thread::Builder::new()
        .name("create_db_accounts1".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            create_db_accounts_from_main_trading_account1(sk);
        })
        .unwrap();
    let create_db_accounts2 = thread::Builder::new()
        .name("create_db_accounts2".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            create_db_accounts_from_main_trading_account2(sk);
        })
        .unwrap();

    let limit_order_service = thread::Builder::new()
        .name("limit_order_service".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            loop {
                let _ = limit_order_service_based_on_db_accounts(sk, 20, 3);
                let _ = sleep(Duration::from_secs(10));
            }
        })
        .unwrap();

    let market_order_service = thread::Builder::new()
        .name("market_order_service".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            loop {
                let _ = market_order_service_based_on_db_accounts(sk, 20, 3);
                let _ = sleep(Duration::from_secs(10));
            }
        })
        .unwrap();

    let settle_market_orders = thread::Builder::new()
        .name("settle_market_orders".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            loop {
                let _ = sleep(Duration::from_secs(10));
                let _ = settle_market_orders_based_on_db_orders(sk, 5, 3);
            }
        })
        .unwrap();

    let _find_executed_limit_orders = thread::Builder::new()
        .name("find_executed_limit_orders".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            let _ = find_executed_limit_orders_service(sk);
        })
        .unwrap();
    // let _update_settled_orders = thread::Builder::new()
    //     .name("update_settled_orders".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         update_settled_orders_db(sk);
    //     })
    //     .unwrap();
    loop {
        sleep(Duration::from_secs(600))
    }
}

fn create_db_accounts_from_main_trading_account1(sk: RistrettoSecretKey) {
    // let client_address = "0c3a5d19bbecb92c4067acf956c3318df84f047b082b5d64a735cb3500c81a3a1a127d438d5a441cd86b3175ead304a436860e8007c86894586c56712678806e67f270a0f9";
    let client_address = &ACCOUNT_1.clone();
    // let initial_amount: u64 = 532800;
    let env_var_name = "ACCOUNT_1_BALANCE";
    let initial_amount: u64 = get_account_balance(env_var_name);
    twilight_client_sdk::agent::auto_accounts::load_accounts_to_db_from_main_account(
        sk,
        client_address.to_string(),
        initial_amount,
        env_var_name,
    );
}
fn create_db_accounts_from_main_trading_account2(sk: RistrettoSecretKey) {
    // let client_address = "0c66d1f4b17de3aa141542e68a39cdb406759d0dc1a3191d89f76a4fbc8ca9751ee051b3325c445e18af0d25c413485e126623acfda3b2c9c67cbe2601303d146a43027f97";
    let client_address = &ACCOUNT_2.clone();
    let env_var_name = "ACCOUNT_2_BALANCE";
    let initial_amount: u64 = get_account_balance(env_var_name);
    twilight_client_sdk::agent::auto_accounts::load_accounts_to_db_from_main_account(
        sk,
        client_address.to_string(),
        initial_amount,
        env_var_name,
    );
}

fn limit_order_service_based_on_db_accounts(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    twilight_client_sdk::agent::auto_orders::limit_order_service(sk, number_orders, sleep_duration)
}

fn market_order_service_based_on_db_accounts(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    twilight_client_sdk::agent::auto_orders::market_order_service(sk, number_orders, sleep_duration)
}

fn settle_market_orders_based_on_db_orders(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    twilight_client_sdk::agent::auto_orders::settle_market_orders_service(
        sk,
        number_orders,
        sleep_duration,
        "MARKET".to_string(),
    )
}

fn find_executed_limit_orders_service(sk: RistrettoSecretKey) -> Result<String, String> {
    twilight_client_sdk::agent::auto_orders::find_executed_limit_orders_service(sk)
}

fn update_settled_orders_db(sk: RistrettoSecretKey) {
    twilight_client_sdk::agent::auto_accounts::update_settled_accounts_in_db_service(sk)
}
