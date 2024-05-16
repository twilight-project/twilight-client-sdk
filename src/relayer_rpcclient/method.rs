use std::process::Output;

use serde::{Deserialize, Deserializer, Serialize};

use crate::relayer_types::{OrderStatus, OrderType};

/// Serialized as the "method" field of JSON-RPC/HTTP requests.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum Method {
    /// Sends a transaction and immediately returns transaction hash.
    CreateTraderOrder,
    CreateLendOrder,
    ExecuteTraderOrder,
    ExecuteLendOrder,
    CancelTraderOrder,
    transaction_hashes,
    trader_order_info,
    lend_order_info,
}
impl Method {}

// CreateTraderOrder Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetCreateTraderOrderResponse {
    pub msg: String,
    pub id_key: String,
}
impl GetCreateTraderOrderResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetCreateTraderOrderResponse, String> {
        let tx_hash: Result<GetCreateTraderOrderResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(response),

                _ => Err("errror".to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// CreateTraderOrder Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetCreateLendOrderResponse {
    pub msg: String,
    pub id_key: String,
}
impl GetCreateLendOrderResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetCreateLendOrderResponse, String> {
        let tx_hash: Result<GetCreateLendOrderResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(response),

                _ => Err("errror".to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// CreateTraderOrder Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetExecuteTraderOrderResponse {
    pub msg: String,
    pub id_key: String,
}
impl GetExecuteTraderOrderResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetExecuteTraderOrderResponse, String> {
        let tx_hash: Result<GetExecuteTraderOrderResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(response),

                _ => Err("errror".to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// CreateTraderOrder Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetExecuteLendOrderResponse {
    pub msg: String,
    pub id_key: String,
}
impl GetExecuteLendOrderResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetExecuteLendOrderResponse, String> {
        let tx_hash: Result<GetExecuteLendOrderResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(response),

                _ => Err("errror".to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// CreateTraderOrder Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetCancelTraderOrderResponse {
    pub msg: String,
    pub id_key: String,
}
impl GetCancelTraderOrderResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetCancelTraderOrderResponse, String> {
        let tx_hash: Result<GetCancelTraderOrderResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(response),

                _ => Err("errror".to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}

// Gwt transaction hash response Vec<TxHash>
fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let key = Option::<T>::deserialize(de)?;
    Ok(key.unwrap_or_default())
}
#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionHashArgs {
    TxId {
        id: String,
        #[serde(deserialize_with = "null_to_default")]
        status: Option<OrderStatus>,
    },
    AccountId {
        id: String,
        #[serde(deserialize_with = "null_to_default")]
        status: Option<OrderStatus>,
    },
    RequestId {
        id: String,
        #[serde(deserialize_with = "null_to_default")]
        status: Option<OrderStatus>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxHash {
    pub id: i64,
    pub order_id: String,
    pub account_id: String,
    pub tx_hash: String,
    pub order_type: OrderType,
    pub order_status: OrderStatus,
    pub datetime: String,
    pub output: Option<String>,
    pub request_id: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetTransactionHashResponse {
    pub result: Vec<TxHash>,
}
impl GetTransactionHashResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetTransactionHashResponse, String> {
        let tx_hash: Result<GetTransactionHashResponse, String> = match resp.result {
            Ok(response) => {
                println!("response data0 :{:?}", response);
                match serde_json::from_value(response) {
                    Ok(response_vec) => {
                        println!("response data :{:?}", response_vec);
                        Ok(GetTransactionHashResponse {
                            result: response_vec,
                        })
                    }

                    Err(arg) => {
                        println!("Error arg :{:?}", arg);
                        Err("errror".to_string())
                    }
                }
            }
            Err(arg) => Err(arg.to_string()),
        };

        tx_hash
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ByteRec {
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestResponse {
    pub msg: String,
    pub id_key: String,
}
impl RequestResponse {
    pub fn new(msg: String, id_key: String) -> Self {
        RequestResponse { msg, id_key }
    }
}
