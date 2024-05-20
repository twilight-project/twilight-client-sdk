use crate::relayer_types::{LendOrder, OrderStatus, TraderOrder, TxHash};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_f64;
use sha2::{Digest, Sha256};
use std::{hash::Hash, time::SystemTime};
use uuid::Uuid;
/// Serialized as the "method" field of JSON-RPC/HTTP requests.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum Method {
    /// Sends a transaction and immediately returns transaction hash.
    CreateTraderOrder,
    CreateLendOrder,
    ExecuteTraderOrder,
    ExecuteLendOrder,
    CancelTraderOrder,
    #[allow(non_camel_case_types)]
    transaction_hashes,
    #[allow(non_camel_case_types)]
    trader_order_info,
    #[allow(non_camel_case_types)]
    lend_order_info,
    #[allow(non_camel_case_types)]
    btc_usd_price,
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

// Get transaction hash response Vec<TxHash>

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionHashArgs {
    TxId {
        id: String,
        status: Option<OrderStatus>,
    },
    AccountId {
        id: String,
        status: Option<OrderStatus>,
    },
    RequestId {
        id: String,
        status: Option<OrderStatus>,
    },
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
            Ok(response) => match serde_json::from_value(response) {
                Ok(response_vec) => Ok(GetTransactionHashResponse {
                    result: response_vec,
                }),

                Err(arg) => Err(arg.to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };

        tx_hash
    }
}

// Query trader order info Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetTraderOrderInfoResponse {
    pub result: TraderOrder,
}
impl GetTraderOrderInfoResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetTraderOrderInfoResponse, String> {
        let tx_hash: Result<GetTraderOrderInfoResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(GetTraderOrderInfoResponse { result: response }),

                Err(arg) => Err(arg.to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// Query trader order info Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetLendOrderInfoResponse {
    pub result: LendOrder,
}
impl GetLendOrderInfoResponse {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetLendOrderInfoResponse, String> {
        let tx_hash: Result<GetLendOrderInfoResponse, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(GetLendOrderInfoResponse { result: response }),

                Err(arg) => Err(arg.to_string()),
            },
            Err(arg) => Err(arg.to_string()),
        };
        tx_hash
    }
}
// Query trader order info Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetBTCPRice {
    pub result: BTCPrice,
}
impl GetBTCPRice {
    pub fn get_response(
        resp: crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
    ) -> Result<GetBTCPRice, String> {
        let tx_hash: Result<GetBTCPRice, String> = match resp.result {
            Ok(response) => match serde_json::from_value(response) {
                Ok(response) => Ok(GetBTCPRice { result: response }),

                Err(arg) => Err(arg.to_string()),
            },
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BTCPrice {
    pub id: i64,
    #[serde(deserialize_with = "as_f64")]
    pub price: f64,
    pub timestamp: String,
}
impl RequestResponse {
    pub fn new(msg: String, id_key: String) -> Self {
        RequestResponse {
            msg,
            id_key: RequestID::new(id_key).get_id(),
        }
    }
    pub fn get_id(&self) -> String {
        self.id_key.clone()
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct RequestID {
    uuid: Uuid,
    public_key: String,
    timestamp: String,
}
impl RequestID {
    pub fn new(public_key: String) -> RequestID {
        RequestID {
            uuid: Uuid::new_v4(),
            public_key: public_key,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros()
                .to_string(),
        }
    }
    pub fn get_id(&self) -> String {
        let Ok(bytes) = bincode::serialize(&self) else {
            return Uuid::new_v4().into();
        };
        let mut sha256 = Sha256::new();
        sha256.update(hex::encode(bytes));
        let result: String = format!("REQID{:X}", sha256.finalize());
        result
    }
}

#[cfg(test)]
mod test {
    use super::RequestResponse;
    // use hex_literal::hex;
    use sha2::{Digest, Sha256};
    #[test]
    fn request_id_test() {
        let id  =  RequestResponse::new("order success".to_string(), "0ce8ffc7587e8ac1c8328f44b5219834b98125c7ef176a31f3ac7201b749ad913b84b8600e6d2a6f607454a9527238f6978f31102d308f3acb3599e7b725163117df5cb11c".to_string());
        println!("id: {:?}", id.get_id());
    }
}
