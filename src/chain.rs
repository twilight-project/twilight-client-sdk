use hex;
use transactionapi::rpcclient::{method::*, txrequest::*};
use zkvm::zkos_types::{IOType, Input, Output, OutputCoin, Utxo};
lazy_static! {
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_URL").expect("missing environment variable ZKOS_SERVER_URL");
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
    fn get_coin_output_by_utxo_id_hex_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let utxo = "bc289213b0185f115e88bec0900a80669243980e9666e11c7cbb14fc1271b0bc00".to_string();
        println!("output:{:?}", get_coin_output_by_utxo_id_hex(utxo));
    }
}
