use lazy_static::lazy_static;
use quisquislib::keys::SecretKey;
use quisquislib::ristretto::RistrettoSecretKey;
use std::{
    thread::{self, sleep},
    time::Duration,
};
lazy_static! {
    pub static ref RELAYER_SEED_PHRASE: String = std::env::var("RELAYER_SEED_PHRASE")
        .expect("missing environment variable RELAYER_SEED_PHRASE");
}

fn main() {
    dotenv::dotenv().expect("Failed loading dotenv");
    let sk = <RistrettoSecretKey as SecretKey>::from_bytes(RELAYER_SEED_PHRASE.as_bytes());

    // let create_db_accounts = thread::Builder::new()
    //     .name("create_db_accounts".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         create_db_accounts_from_main_trading_account(sk);
    //     })
    //     .unwrap();
    // let create_db_accounts1 = thread::Builder::new()
    //     .name("create_db_accounts1".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         create_db_accounts_from_main_trading_account1(sk);
    //     })
    //     .unwrap();
    // let create_db_accounts2 = thread::Builder::new()
    //     .name("create_db_accounts2".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         create_db_accounts_from_main_trading_account2(sk);
    //     })
    //     .unwrap();

    // let limit_order_service = thread::Builder::new()
    //     .name("limit_order_service".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         loop {
    //             let _ = limit_order_service_based_on_db_accounts(sk, 20, 3);
    //             let _ = sleep(Duration::from_secs(10));
    //         }
    //     })
    //     .unwrap();

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
                let _ = settle_market_orders_based_on_db_orders(sk, 20, 7);
                let _ = sleep(Duration::from_secs(10));
            }
        })
        .unwrap();

    // let find_executed_limit_orders = thread::Builder::new()
    //     .name("find_executed_limit_orders".to_string())
    //     .spawn(move || {
    //         // Create accounts from main trading account
    //         find_executed_limit_orders_service(sk);
    //     })
    //     .unwrap();
    let update_settled_orders = thread::Builder::new()
        .name("update_settled_orders".to_string())
        .spawn(move || {
            // Create accounts from main trading account
            update_settled_orders_db(sk);
        })
        .unwrap();
    loop {
        sleep(Duration::from_secs(600))
    }
}

fn create_db_accounts_from_main_trading_account(sk: RistrettoSecretKey) {
    let client_address = "0cc6e3565f35f8f71815c7538ab86668f453b755bf25152e5b617cf12c4fcb4057640eceac9c41c54fdfce98f08c21a09bce78932250501003e6448753dceb37797da22edc";
    let initial_amount: u64 = 337600;

    zkos_client_wallet::agent::auto_accounts::load_accounts_to_db_from_main_account(
        sk,
        client_address.to_string(),
        initial_amount,
    );
}
fn create_db_accounts_from_main_trading_account1(sk: RistrettoSecretKey) {
    // let client_address = "0cb0d009d3df5d08eeabc8ca05830e5f45cbdf5f54639ce1b7e4b9e169efb0ed5216fc25da8c8546f161e6bf0ed87f75c9d61593c1d8d8f1ecd2917f0a529a653e30c1eb4b";
    // // let initial_amount: u64 = 1714300;
    // // let initial_amount: u64 = 1387100; //order +- 800
    // // let initial_amount: u64 = 1380700; //order +- 800 1383900
    // // let initial_amount: u64 = 1360700; //order +- 800 1383900
    // // let initial_amount: u64 = 782300; //order +- 800 1383900
    // let initial_amount: u64 = 779900; //order +- 800 1383900
    // let client_address = "0c6a729c97a6ceb43278aa722aee90a69f43ec4d52722ae8d60289f9daa28ab52f3e54d482fb64fe987fb6c06f9f753a162e349f6ae3e280fe8820d96ee7edfe103d3ae4a2";
    // let initial_amount: u64 = 720000; //order +- 800 1383900 773600 728000
    let client_address = "0c3a5d19bbecb92c4067acf956c3318df84f047b082b5d64a735cb3500c81a3a1a127d438d5a441cd86b3175ead304a436860e8007c86894586c56712678806e67f270a0f9";
    let initial_amount: u64 = 532800; //order +- 800 1383900 773600 728000

    zkos_client_wallet::agent::auto_accounts::load_accounts_to_db_from_main_account(
        sk,
        client_address.to_string(),
        initial_amount,
    );
}
fn create_db_accounts_from_main_trading_account2(sk: RistrettoSecretKey) {
    // let client_address = "0cb0d009d3df5d08eeabc8ca05830e5f45cbdf5f54639ce1b7e4b9e169efb0ed5216fc25da8c8546f161e6bf0ed87f75c9d61593c1d8d8f1ecd2917f0a529a653e30c1eb4b";
    // // let initial_amount: u64 = 1714300;
    // // let initial_amount: u64 = 1387100; //order +- 800
    // // let initial_amount: u64 = 1380700; //order +- 800 1383900
    // // let initial_amount: u64 = 1360700; //order +- 800 1383900
    // // let initial_amount: u64 = 782300; //order +- 800 1383900
    // let initial_amount: u64 = 779900; //order +- 800 1383900
    // let client_address = "0c6a729c97a6ceb43278aa722aee90a69f43ec4d52722ae8d60289f9daa28ab52f3e54d482fb64fe987fb6c06f9f753a162e349f6ae3e280fe8820d96ee7edfe103d3ae4a2";
    // let initial_amount: u64 = 720000; //order +- 800 1383900 773600 728000
    let client_address = "0c66d1f4b17de3aa141542e68a39cdb406759d0dc1a3191d89f76a4fbc8ca9751ee051b3325c445e18af0d25c413485e126623acfda3b2c9c67cbe2601303d146a43027f97";
    let initial_amount: u64 = 800000; //order +- 800 1383900 773600 728000

    zkos_client_wallet::agent::auto_accounts::load_accounts_to_db_from_main_account(
        sk,
        client_address.to_string(),
        initial_amount,
    );
}

fn limit_order_service_based_on_db_accounts(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    zkos_client_wallet::agent::auto_orders::limit_order_service(sk, number_orders, sleep_duration)
}

fn market_order_service_based_on_db_accounts(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    zkos_client_wallet::agent::auto_orders::market_order_service(sk, number_orders, sleep_duration)
}

fn settle_market_orders_based_on_db_orders(
    sk: RistrettoSecretKey,
    number_orders: i64,
    sleep_duration: u64,
) -> Result<String, String> {
    zkos_client_wallet::agent::auto_orders::settle_market_orders_service(
        sk,
        number_orders,
        sleep_duration,
    )
}

fn find_executed_limit_orders_service(sk: RistrettoSecretKey) -> Result<String, String> {
    zkos_client_wallet::agent::auto_orders::find_executed_limit_orders_service(sk)
}

fn update_settled_orders_db(sk: RistrettoSecretKey) {
    zkos_client_wallet::agent::auto_accounts::update_settled_accounts_in_db_service(sk)
}
