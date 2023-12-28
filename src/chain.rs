use hex;
use transactionapi::rpcclient::{method::*, txrequest::*};
use zkvm::{
    zkos_types::{Input, Output, Utxo},
    String as ZkvmString,
};

lazy_static! {
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_URL").expect("missing environment variable ZKOS_SERVER_URL");
}

pub fn get_transaction_coin_input_from_address(address_hex: String) -> Result<Input, String> {
    let coin_utxo_vec_result = get_coin_utxo_by_address_hex(address_hex);
    match coin_utxo_vec_result {
        Ok(utxo_vec_hex) => {
            if utxo_vec_hex.len() > 0 {
                let coin_output_result = get_coin_output_by_utxo_id_hex(utxo_vec_hex[0].clone());
                match coin_output_result {
                    Ok(coin_output) => {
                        let input_result = crate::util::create_input_coin_from_output_coin(
                            coin_output,
                            utxo_vec_hex[0].clone(),
                        );
                        match input_result {
                            Ok(input) => Ok(input),
                            Err(_) => return Err("create_input_from_output error")?,
                        }
                    }
                    Err(_) => return Err("No output found for given utxo")?,
                }
            } else {
                return Err("No utxo found")?;
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_transaction_memo_input_from_address(
    address_hex: String,
    memo_output: Output,
    withdraw_amount: u64,
) -> Result<Input, String> {
    let coin_utxo_vec_result = get_memo_utxo_by_address_hex(address_hex);
    match coin_utxo_vec_result {
        Ok(utxo_vec_hex) => {
            if utxo_vec_hex.len() > 0 {
                let input_result = crate::util::create_input_memo_from_output_memo(
                    memo_output,
                    utxo_vec_hex[0].clone(),
                    withdraw_amount,
                );
                match input_result {
                    Ok(input) => Ok(input),
                    Err(_) => return Err("create_input_from_output error".to_string()),
                }
            } else {
                return Err("No utxo found".to_string());
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
/// get transaction state input from chain based on address_hex
///
pub fn get_transaction_state_input_from_address(
    address_hex: String,
    output_state: Output,
    script_data: Option<Vec<ZkvmString>>,
) -> Result<Input, String> {
    let state_utxo_vec_result = get_state_utxo_by_address_hex(address_hex);
    match state_utxo_vec_result {
        Ok(utxo_vec_hex) => {
            if utxo_vec_hex.len() > 0 {
                // create input state

                match crate::util::create_input_state_from_output_state(
                    output_state,
                    utxo_vec_hex[0].clone(),
                    script_data,
                ) {
                    Ok(input) => Ok(input),
                    Err(_) => return Err("create_input_from_output error".to_string()),
                }
            } else {
                return Err("No utxo found")?;
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_coin_utxo_by_address_hex(address_hex: String) -> Result<Vec<String>, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![address_hex], Method::getUtxos);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => {
            let response: Vec<Utxo> = GetUtxosResponse::get_response(rpc_response);
            let mut result: Vec<String> = Vec::new();
            for utxo in response {
                result.push(hex::encode(bincode::serialize(&utxo).unwrap()));
            }
            Ok(result)
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_coin_output_by_utxo_id_hex(utxo_id_hex: String) -> Result<Output, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![utxo_id_hex], Method::getOutput);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => match GetCoinOutputResponse::get_response(rpc_response).all_utxo {
            Some(output) => Ok(output),
            None => Err("No Output Found for given utxo".to_string()),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_memo_utxo_by_address_hex(address_hex: String) -> Result<Vec<String>, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![address_hex], Method::getMemoUtxos);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => {
            let response: Vec<Utxo> = GetMemoUtxosResponse::get_response(rpc_response);
            let mut result: Vec<String> = Vec::new();
            for utxo in response {
                result.push(hex::encode(bincode::serialize(&utxo).unwrap()));
            }
            Ok(result)
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_memo_output_by_utxo_id_hex(utxo_id_hex: String) -> Result<Output, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![utxo_id_hex], Method::getMemoOutput);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => match GetMemoOutputResponse::get_response(rpc_response).all_utxo {
            Some(output) => Ok(output),
            None => Err("No Output Found for given utxo".to_string()),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_state_utxo_by_address_hex(address_hex: String) -> Result<Vec<String>, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![address_hex], Method::getStateUtxos);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => {
            let response: Vec<Utxo> = GetStateUtxosResponse::get_response(rpc_response);
            let mut result: Vec<String> = Vec::new();
            for utxo in response {
                result.push(hex::encode(bincode::serialize(&utxo).unwrap()));
            }
            Ok(result)
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_state_output_by_utxo_id_hex(utxo_id_hex: String) -> Result<Output, String> {
    let tx_send: RpcBody<Vec<String>> = RpcRequest::new(vec![utxo_id_hex], Method::getStateOutput);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => match GetStateOutputResponse::get_response(rpc_response).all_utxo {
            Some(output) => Ok(output),
            None => Err("No Output Found for given utxo".to_string()),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}

pub fn tx_commit_broadcast_transaction(tx: transaction::Transaction) -> Result<String, String> {
    let tx_send: RpcBody<transaction::Transaction> = RpcRequest::new(tx, Method::txCommit);
    let res = tx_send.send(ZKOS_SERVER_URL.clone());
    match res {
        Ok(rpc_response) => match GetTxCommit::get_txhash(rpc_response) {
            Ok(hash) => Ok(hash),
            Err(arg) => Err(arg),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn get_coin_utxo_by_address_hex_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let address="0c0a2555a4de4e44e9f10e8d682b1e63f58216ec3ae0d5947e6c65fd1efa952433e0a226db8e1ab54305ce578e39a305871ada6037e76a2ba74bc86e5c8011d736be751ed4".to_string();

        println!("utxo_vec:{:?}", get_coin_utxo_by_address_hex(address));
    }
    #[test]
    fn get_state_utxo_by_address_hex_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let address="0c9ee2f0ef12a12745c0ad1111363f82134c426964ea2e985e6c3c3f7a0ee6d72b867e73d765be00ff4c8866ca142b3e3aa82dd75079b5ee514baf4e2ac7fc7e75f2daabc9".to_string();
        println!("utxo_vec:{:?}", get_state_utxo_by_address_hex(address));
    }

    #[test]
    fn get_coin_output_by_utxo_id_hex_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let utxo = "bc289213b0185f115e88bec0900a80669243980e9666e11c7cbb14fc1271b0bc00".to_string();
        println!("output:{:?}", get_coin_output_by_utxo_id_hex(utxo));
    }
    #[test]
    fn get_state_output_by_utxo_id_hex_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let utxo = "1e5010f69f1fce18e5e93e715358112e35e75ce2118939f0e7a7baecfc15d1ab01".to_string();
        println!("output:{:?}", get_state_output_by_utxo_id_hex(utxo));
    }
}
