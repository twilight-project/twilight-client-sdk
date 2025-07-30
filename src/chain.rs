//! Provides functions for interacting with a ZkOS blockchain node via RPC calls.
//!
//! This module abstracts the details of JSON-RPC communication for common on-chain
//! operations such as fetching UTXOs (Coin, Memo, State), retrieving full `Output`
//! data, and broadcasting transactions.

use crate::relayer_rpcclient::method::{UtxoDetailResponse, UtxoRequest};
use curve25519_dalek::scalar::Scalar;
use hex;
use transactionapi::rpcclient::{method::*, txrequest::*};
use zkvm::{
    zkos_types::{Input, Output, Utxo},
    IOType, String as ZkvmString,
};

lazy_static! {
    /// The URL of the ZkOS RPC server, loaded from the `ZKOS_SERVER_URL` environment variable.
    ///
    /// # Panics
    /// Panics if the `ZKOS_SERVER_URL` environment variable is not set at runtime.
    pub static ref ZKOS_SERVER_URL: String =
        std::env::var("ZKOS_SERVER_STAGING_URL").expect("missing environment variable ZKOS_SERVER_STAGING_URL");
}

/// Fetches the first available coin UTXO for a given address and converts it into a spendable `Input`.
///
/// This is a convenience function that chains `get_coin_utxo_by_address_hex` and
/// `get_coin_output_by_utxo_id_hex` to prepare a coin for use in a new transaction.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query for coin UTXOs.
///
/// # Returns
/// A `Result` containing the `Input` on success, or an error string if no UTXO is found
/// or if any of the underlying RPC calls fail.
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

pub fn get_transaction_coin_input_from_address_fast(address_hex: String) -> Result<Input, String> {
    let coin_utxo_result = get_utxo_details_by_address(address_hex, IOType::Coin);
    match coin_utxo_result {
        Ok(utxo_detail_response) => {
            let out_coin = match utxo_detail_response.output.as_out_coin() {
                Some(coin) => coin.clone(),
                None => return Err("Invalid Output:: Not a Coin Output")?,
            };
            let inp = Input::coin(zkvm::InputData::coin(
                utxo_detail_response.id.clone(),
                out_coin,
                0,
            ));
            Ok(inp)
        }
        Err(arg) => {
            Err(format!("GetUtxoDetailError in transaction_coin_input fn: {:?}", arg).into())
        }
    }
}

/// Fetches the first available memo UTXO for a given address and converts it into a spendable `Input`.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query for memo UTXOs.
/// - `memo_output`: The `Output` of the memo being spent. This is required to construct the input.
/// - `withdraw_amount`: The amount being withdrawn from the memo.
///
/// # Returns
/// A `Result` containing a tuple of the `(Input, Scalar)` on success, where the scalar is the
/// blinding factor used. Returns an error string on failure.
pub fn get_transaction_memo_input_from_address(
    address_hex: String,
    memo_output: Output,
    withdraw_amount: u64,
) -> Result<(Input, Scalar), String> {
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
/// Fetches the first available state UTXO for an address and converts it into a spendable `Input`.
///
/// This function is used to interact with smart contracts by preparing the current state
/// as an input for a new transaction.
///
/// # Parameters
/// - `address_hex`: The hex-encoded script address of the contract state to query.
/// - `output_state`: The `Output` of the state being spent.
/// - `script_data`: Optional data to be passed to the smart contract's script.
///
/// # Returns
/// A `Result` containing the state `Input` on success, or an error string on failure.
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
/// Fetches all coin UTXO IDs for a given address.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query.
///
/// # Returns
/// A `Result` containing a vector of hex-encoded UTXO ID strings on success, or an error string on failure.
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

pub fn get_utxo_id_by_address(
    address_hex: String,
    out_type: IOType,
) -> Result<crate::relayer_rpcclient::method::GetUtxoIdHex, String> {
    let utxo_request_arg = UtxoRequest {
        address_or_id: address_hex.clone(),
        input_type: out_type,
    };

    let tx_send: crate::relayer_rpcclient::txrequest::RpcBody<UtxoRequest> =
        crate::relayer_rpcclient::txrequest::RpcRequest::new(
            utxo_request_arg,
            crate::relayer_rpcclient::method::Method::get_utxos_id,
        );
    let res: Result<
        crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
        reqwest::Error,
    > = crate::relayer_rpcclient::txrequest::RpcRequest::send(tx_send, ZKOS_SERVER_URL.clone());

    let response_unwrap = match res {
        Ok(rpc_response) => {
            match crate::relayer_rpcclient::method::GetUtxoIdHex::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    };
    response_unwrap
}

/// Fetches the full `Output` data for a given coin UTXO ID.
///
/// # Parameters
/// - `utxo_id_hex`: The hex-encoded UTXO ID of the coin.
///
/// # Returns
/// A `Result` containing the `Output` on success, or an error string on failure.

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
/// Fetches all memo UTXO IDs for a given address.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query.
///
/// # Returns
/// A `Result` containing a vector of hex-encoded UTXO ID strings on success, or an error string on failure.
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
/// Fetches the full `Output` data for a given memo UTXO ID.
///
/// # Parameters
/// - `utxo_id_hex`: The hex-encoded UTXO ID of the memo.
///
/// # Returns
/// A `Result` containing the `Output` on success, or an error string on failure.
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
/// Fetches all state UTXO IDs for a given address.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query.
///
/// # Returns
/// A `Result` containing a vector of hex-encoded UTXO ID strings on success, or an error string on failure.
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
/// Fetches the full `Output` data for a given state UTXO ID.
///
/// # Parameters
/// - `utxo_id_hex`: The hex-encoded UTXO ID of the state.
///
/// # Returns
/// A `Result` containing the `Output` on success, or an error string on failure.
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

/// Broadcasts a transaction to the network.
///
/// # Parameters
/// - `tx`: The `transaction::Transaction` to be broadcast.
///
/// # Returns
/// A `Result` containing the transaction hash as a string on successful broadcast,
/// or an error string on failure.
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

/// Fetches detailed UTXO information (both UTXO and Output) for a given address and type.
///
/// This is a more general-purpose function for querying different types of UTXOs.
///
/// # Parameters
/// - `address_hex`: The hex-encoded address to query.
/// - `out_type`: The `IOType` to query for (`Coin`, `Memo`, or `State`).
///
/// # Returns
/// A `Result` containing a `UtxoDetailResponse` on success, or an error string on failure.
pub fn get_utxo_details_by_address(
    address_hex: String,
    out_type: IOType,
) -> Result<UtxoDetailResponse, String> {
    let utxo_request_arg = UtxoRequest {
        address_or_id: address_hex.clone(),
        input_type: out_type,
    };

    let tx_send: crate::relayer_rpcclient::txrequest::RpcBody<UtxoRequest> =
        crate::relayer_rpcclient::txrequest::RpcRequest::new(
            utxo_request_arg,
            crate::relayer_rpcclient::method::Method::get_utxos_detail,
        );
    let res: Result<
        crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
        reqwest::Error,
    > = crate::relayer_rpcclient::txrequest::RpcRequest::send(tx_send, ZKOS_SERVER_URL.clone());

    let response_unwrap = match res {
        Ok(rpc_response) => match UtxoDetailResponse::get_response(rpc_response) {
            Ok(response) => Ok(response),
            Err(arg) => Err(arg),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    };
    response_unwrap
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn get_coin_utxo_by_address_hex_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let address = std::env::var("TEST_ADDRESS")
            .unwrap_or_else(|_| "0c0a2555a4de4e44e9f10e8d682b1e63f58216ec3ae0d5947e6c65fd1efa952433e0a226db8e1ab54305ce578e39a305871ada6037e76a2ba74bc86e5c8011d736be751ed4".to_string());

        println!("utxo_vec:{:?}", get_coin_utxo_by_address_hex(address));
    }
    #[test]
    fn get_state_utxo_by_address_hex_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let address = std::env::var("TEST_STATE_ADDRESS")
            .unwrap_or_else(|_| "0c9ee2f0ef12a12745c0ad1111363f82134c426964ea2e985e6c3c3f7a0ee6d72b867e73d765be00ff4c8866ca142b3e3aa82dd75079b5ee514baf4e2ac7fc7e75f2daabc9".to_string());
        println!("utxo_vec:{:?}", get_state_utxo_by_address_hex(address));
    }

    #[test]
    fn get_coin_output_by_utxo_id_hex_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let utxo = std::env::var("TEST_COIN_UTXO").unwrap_or_else(|_| {
            "bc289213b0185f115e88bec0900a80669243980e9666e11c7cbb14fc1271b0bc00".to_string()
        });
        println!("output:{:?}", get_coin_output_by_utxo_id_hex(utxo));
    }
    #[test]
    fn get_state_output_by_utxo_id_hex_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let utxo = std::env::var("TEST_STATE_UTXO").unwrap_or_else(|_| {
            "1e5010f69f1fce18e5e93e715358112e35e75ce2118939f0e7a7baecfc15d1ab01".to_string()
        });
        println!("output:{:?}", get_state_output_by_utxo_id_hex(utxo));
    }
}
