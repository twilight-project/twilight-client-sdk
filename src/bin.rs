
use quisquislib::keys::SecretKey;
use quisquislib::ristretto:: RistrettoSecretKey;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref RELAYER_SEED_PHRASE: String = std::env::var("RELAYER_SEED_PHRASE")
        .expect("missing environment variable RELAYER_SEED_PHRASE");
}

fn main() {
    dotenv::dotenv().expect("Failed loading dotenv");
    let sk = <RistrettoSecretKey as SecretKey>::from_bytes(RELAYER_SEED_PHRASE.as_bytes());
    
    // Create accounts from main trading account
    //create_db_accounts_from_main_trading_account(sk);
    match limit_order_service_based_on_db_accounts(sk, 50, 1){
        Ok(s) => println!("Success: {}", s),
        Err(e) => println!("Error: {}", e),
    };

    //println!("LONG Order ");
    //println!("SHORT Order ");

    

    // AHMAD TEST FUNCTION FOR ACCOUNTS
    //test_tx_commit_rpc(sk);
   // let client_address = "0c50ce9927c331c653294d0f4f31faea7323855fe742bd5cb72105d11ebebe383db0058b2abb32745547ea815305e93d86c73c3bee9e79db1ffe413dec917332644ac29a0d";
   // let initial_amount: u64 = 10000;
}

fn create_db_accounts_from_main_trading_account(sk: RistrettoSecretKey){
    let client_address = "0c3023e2e4de3790b6f632086916d96bc4cf72c57e5e490567c09bcd24e7561547c0bf4e2050597b3bc097bd3e2100eb29e4407cdbc1a043cc92e255e5eadf026df814f9a6";
    let initial_amount: u64 = 32000;
    zkos_client_wallet::agent::auto_accounts::load_accounts_to_db_from_main_account(sk, client_address.to_string(), initial_amount);
}


fn limit_order_service_based_on_db_accounts(sk: RistrettoSecretKey, number_orders: i64, sleep_duration: u64)-> Result<String, String> {
    zkos_client_wallet::agent::auto_orders::limit_order_service(sk, number_orders, sleep_duration)
}
