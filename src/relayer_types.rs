use crate::relayer_rpcclient::method::*;
use crate::relayer_rpcclient::txrequest::RELAYER_RPC_SERVER_URL;
use crate::relayer_rpcclient::txrequest::{RpcBody, RpcRequest};
use transaction::Transaction;

use curve25519_dalek::scalar::Scalar;
use quisquislib::accounts::SigmaProof;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_f64;
use uuid::Uuid;
use zkschnorr::Signature;
use zkvm::{
    zkos_types::{Input, ValueWitness},
    Output,
};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TXType {
    ORDERTX, //TraderOrder
    LENDTX,  //LendOrder
}

//implement enum for TXType
impl TXType {
    //from string
    pub fn from_str(s: &str) -> Option<TXType> {
        match s {
            "ORDERTX" => Some(TXType::ORDERTX),
            "LENDTX" => Some(TXType::LENDTX),
            _ => None,
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OrderType {
    LIMIT,
    MARKET,
    DARK,
    LEND,
}
impl OrderType {
    //from string
    pub fn from_str(s: &str) -> Option<OrderType> {
        match s {
            "LIMIT" => Some(OrderType::LIMIT),
            "MARKET" => Some(OrderType::MARKET),
            "DARK" => Some(OrderType::DARK),
            "LEND" => Some(OrderType::LEND),
            _ => None,
        }
    }
    pub fn to_str(&self) -> String {
        match self {
            OrderType::LIMIT => "LIMIT".to_string(),
            OrderType::MARKET => "MARKET".to_string(),
            OrderType::DARK => "DARK".to_string(),
            OrderType::LEND => "LEND".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PositionType {
    LONG,
    SHORT,
}
impl PositionType {
    //from string
    pub fn from_str(s: &str) -> Option<PositionType> {
        match s {
            "LONG" => Some(PositionType::LONG),
            "SHORT" => Some(PositionType::SHORT),
            _ => None,
        }
    }
    pub fn to_scalar(&self) -> Scalar {
        match self {
            PositionType::LONG => Scalar::zero() - Scalar::from(1u64),
            PositionType::SHORT => Scalar::from(1u64),
        }
    }
    pub fn to_str(&self) -> String {
        match self {
            PositionType::LONG => "LONG".to_string(),
            PositionType::SHORT => "SHORT".to_string(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OrderStatus {
    SETTLED,
    LENDED,
    LIQUIDATE,
    CANCELLED,
    PENDING, // change it to New
    FILLED,  //executed on price ticker
    DuplicateOrder,
    UtxoError,
    Error,
    NoResponseFromChain,
    RejectedFromChain,
    BincodeError,
    HexCodeError,
    SerializationError,
    RequestSubmitted,
    OrderNotFound,
}
impl OrderStatus {
    //from string
    pub fn from_str(s: &str) -> Option<OrderStatus> {
        match s {
            "SETTLED" => Some(OrderStatus::SETTLED),
            "LENDED" => Some(OrderStatus::LENDED),
            "LIQUIDATE" => Some(OrderStatus::LIQUIDATE),
            "CANCELLED" => Some(OrderStatus::CANCELLED),
            "PENDING" => Some(OrderStatus::PENDING),
            "FILLED" => Some(OrderStatus::FILLED),
            "DuplicateError" => Some(OrderStatus::DuplicateOrder),
            "UtxoError" => Some(OrderStatus::UtxoError),
            "Error" => Some(OrderStatus::Error),
            "NoResponseFromChain" => Some(OrderStatus::NoResponseFromChain),
            "BincodeError" => Some(OrderStatus::BincodeError),
            "HexCodeError" => Some(OrderStatus::HexCodeError),
            "SerializationError" => Some(OrderStatus::SerializationError),
            "OrderNotFound" => Some(OrderStatus::OrderNotFound),
            "RejectedFromChain" => Some(OrderStatus::RejectedFromChain),
            _ => None,
        }
    }
    pub fn to_str(&self) -> String {
        match self {
            OrderStatus::SETTLED => "SETTLED".to_string(),
            OrderStatus::LENDED => "LENDED".to_string(),
            OrderStatus::LIQUIDATE => "LIQUIDATE".to_string(),
            OrderStatus::CANCELLED => "CANCELLED".to_string(),
            OrderStatus::PENDING => "PENDING".to_string(),
            OrderStatus::FILLED => "FILLED".to_string(),
            OrderStatus::DuplicateOrder => "DuplicateError".to_string(),
            OrderStatus::UtxoError => "UtxoError".to_string(),
            OrderStatus::Error => "Error".to_string(),
            OrderStatus::NoResponseFromChain => "NoResponseFromChain".to_string(),
            OrderStatus::BincodeError => "BincodeError".to_string(),
            OrderStatus::HexCodeError => "HexCodeError".to_string(),
            OrderStatus::SerializationError => "SerializationError".to_string(),
            OrderStatus::RequestSubmitted => "RequestSubmitted".to_string(),
            OrderStatus::OrderNotFound => "OrderNotFound".to_string(),
            OrderStatus::RejectedFromChain => "RejectedFromChain".to_string(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RequestStatus {
    SETTLED,
    LENDED,
    LIQUIDATE,
    CANCELLED,
    PENDING, // change it to New
    FILLED,
    DuplicateOrder,
    UtxoError,
    Error,
    NoResponseFromChain,
    BincodeError,
    HexCodeError,
    SerializationError,
    RequestSubmitted,
    OrderNotFound,
    RejectedFromChain,
}
impl RequestStatus {
    //from string
    pub fn from_str(s: &str) -> Option<RequestStatus> {
        match s {
            "SETTLED" => Some(RequestStatus::SETTLED),
            "LENDED" => Some(RequestStatus::LENDED),
            "LIQUIDATE" => Some(RequestStatus::LIQUIDATE),
            "CANCELLED" => Some(RequestStatus::CANCELLED),
            "PENDING" => Some(RequestStatus::PENDING),
            "FILLED" => Some(RequestStatus::FILLED),
            "DuplicateError" => Some(RequestStatus::DuplicateOrder),
            "UtxoError" => Some(RequestStatus::UtxoError),
            "Error" => Some(RequestStatus::Error),
            "NoResponseFromChain" => Some(RequestStatus::NoResponseFromChain),
            "BincodeError" => Some(RequestStatus::BincodeError),
            "HexCodeError" => Some(RequestStatus::HexCodeError),
            "SerializationError" => Some(RequestStatus::SerializationError),
            "OrderNotFound" => Some(RequestStatus::OrderNotFound),
            "RejectedFromChain" => Some(RequestStatus::RejectedFromChain),
            _ => None,
        }
    }
}
/// type defined for Realyer to use in case of client Orders
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMemoTx {
    pub tx: Transaction,
    pub output: Output,
}
impl ClientMemoTx {
    pub fn new(tx: Transaction, output: Output) -> Self {
        Self { tx, output }
    }
    pub fn get_tx(&self) -> Transaction {
        self.tx.clone()
    }
    pub fn get_output(&self) -> Output {
        self.output.clone()
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkosCreateOrder {
    pub input: Input,         //coin type input
    pub output: Output,       // memo type output
    pub signature: Signature, //quisquis signature
    pub proof: SigmaProof,
}
impl ZkosCreateOrder {
    pub fn new(input: Input, output: Output, vw: ValueWitness) -> Self {
        Self {
            input,
            output,
            signature: vw.get_signature().clone(),
            proof: vw.get_value_proof().clone(),
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }
    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateTraderOrder {
    pub account_id: String,
    pub position_type: PositionType,
    pub order_type: OrderType,
    pub leverage: f64,
    pub initial_margin: f64,
    pub available_margin: f64,
    pub order_status: OrderStatus,
    pub entryprice: f64,
    pub execution_price: f64,
}
impl CreateTraderOrder {
    //new from values
    pub fn new(
        account_id: String,
        position_type: String,
        order_type: String,
        leverage: f64,
        initial_margin: f64,
        available_margin: f64,
        order_status: String,
        entryprice: f64,
        execution_price: f64,
    ) -> CreateTraderOrder {
        CreateTraderOrder {
            account_id,
            position_type: PositionType::from_str(&position_type).unwrap(),
            order_type: OrderType::from_str(&order_type).unwrap(),
            leverage,
            initial_margin,
            available_margin,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
            entryprice,
            execution_price,
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTraderOrderZkos {
    pub create_trader_order: CreateTraderOrder,
    pub input: ZkosCreateOrder,
}
impl CreateTraderOrderZkos {
    pub fn new(
        create_trader_order: CreateTraderOrder,
        input: ZkosCreateOrder,
    ) -> CreateTraderOrderZkos {
        CreateTraderOrderZkos {
            create_trader_order,
            input,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }
    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }

    pub fn submit_order(order_msg: String) -> Result<GetCreateTraderOrderResponse, String> {
        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_msg },
            crate::relayer_rpcclient::method::Method::CreateTraderOrder,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(RELAYER_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetCreateTraderOrderResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };
        response_unwrap
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateLendOrder {
    pub account_id: String,
    pub balance: f64,
    pub order_type: OrderType,
    pub order_status: OrderStatus,
    pub deposit: f64,
}
impl CreateLendOrder {
    //new from values
    pub fn new(
        account_id: String,
        balance: f64,
        order_type: String,
        order_status: String,
        deposit: f64,
    ) -> CreateLendOrder {
        CreateLendOrder {
            account_id,
            balance,
            order_type: OrderType::from_str(&order_type).unwrap(),
            order_status: OrderStatus::from_str(&order_status).unwrap(),
            deposit,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateLendOrderZkos {
    pub create_lend_order: CreateLendOrder,
    pub input: ZkosCreateOrder,
}
impl CreateLendOrderZkos {
    pub fn new(create_lend_order: CreateLendOrder, input: ZkosCreateOrder) -> CreateLendOrderZkos {
        CreateLendOrderZkos {
            create_lend_order,
            input,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }

    pub fn submit_order(order_msg: String) -> Result<GetCreateLendOrderResponse, String> {
        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_msg },
            crate::relayer_rpcclient::method::Method::CreateLendOrder,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(RELAYER_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetCreateLendOrderResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };
        response_unwrap
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTraderOrderClientZkos {
    pub create_trader_order: CreateTraderOrder,
    pub tx: Transaction,
}
impl CreateTraderOrderClientZkos {
    pub fn new(create_trader_order: CreateTraderOrder, tx: Transaction) -> Self {
        Self {
            create_trader_order,
            tx,
        }
    }
    pub fn encode_as_hex_string(&self) -> Result<String, String> {
        let byt = bincode::serialize(&self).map_err(|e| format!("Error:{:?}", e))?;
        Ok(hex::encode(&byt))
    }
    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosSettleMsg {
    pub output: Output,       //memo type output
    pub signature: Signature, //quisquis signature
}
impl ZkosSettleMsg {
    pub fn new(output: Output, signature: Signature) -> ZkosSettleMsg {
        ZkosSettleMsg { output, signature }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }
    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExecuteTraderOrder {
    pub account_id: String,
    pub uuid: Uuid,
    pub order_type: OrderType,
    pub settle_margin: f64,
    pub order_status: OrderStatus,
    pub execution_price: f64,
}
impl ExecuteTraderOrder {
    //new from values
    pub fn new(
        account_id: String,
        uuid: Uuid,
        order_type: String,
        settle_margin: f64,
        order_status: String,
        execution_price: f64,
    ) -> ExecuteTraderOrder {
        ExecuteTraderOrder {
            account_id,
            uuid,
            order_type: OrderType::from_str(&order_type).unwrap(),
            settle_margin,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
            execution_price,
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExecuteTraderOrderZkos {
    pub execute_trader_order: ExecuteTraderOrder,
    pub msg: ZkosSettleMsg,
}

impl ExecuteTraderOrderZkos {
    pub fn new(
        execute_trader_order: ExecuteTraderOrder,
        msg: ZkosSettleMsg,
    ) -> ExecuteTraderOrderZkos {
        ExecuteTraderOrderZkos {
            execute_trader_order,
            msg,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }

    pub fn submit_order(order_msg: String) -> Result<GetExecuteTraderOrderResponse, String> {
        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_msg },
            crate::relayer_rpcclient::method::Method::ExecuteTraderOrder,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(RELAYER_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetExecuteTraderOrderResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };
        response_unwrap
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExecuteLendOrder {
    pub account_id: String,
    pub uuid: Uuid,
    pub order_type: OrderType,
    pub settle_withdraw: f64, // % amount to withdraw
    pub order_status: OrderStatus,
    pub poolshare_price: f64, //withdraw pool share price
}
impl ExecuteLendOrder {
    //new from values
    pub fn new(
        account_id: String,
        uuid: Uuid,
        order_type: String,
        settle_withdraw: f64,
        order_status: String,
        poolshare_price: f64,
    ) -> ExecuteLendOrder {
        ExecuteLendOrder {
            account_id,
            uuid,
            order_type: OrderType::from_str(&order_type).unwrap(),
            settle_withdraw,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
            poolshare_price,
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExecuteLendOrderZkos {
    pub execute_lend_order: ExecuteLendOrder,
    pub msg: ZkosSettleMsg,
}
impl ExecuteLendOrderZkos {
    pub fn new(execute_lend_order: ExecuteLendOrder, msg: ZkosSettleMsg) -> Self {
        Self {
            execute_lend_order,
            msg,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }

    pub fn submit_order(order_msg: String) -> Result<GetExecuteLendOrderResponse, String> {
        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_msg },
            crate::relayer_rpcclient::method::Method::ExecuteLendOrder,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(RELAYER_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetExecuteLendOrderResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };
        response_unwrap
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CancelTraderOrder {
    pub account_id: String,
    pub uuid: Uuid,
    pub order_type: OrderType,
    pub order_status: OrderStatus,
}
impl CancelTraderOrder {
    //new from values
    pub fn new(
        account_id: String,
        uuid: Uuid,
        order_type: String,
        order_status: String,
    ) -> CancelTraderOrder {
        CancelTraderOrder {
            account_id,
            uuid,
            order_type: OrderType::from_str(&order_type).unwrap(),
            order_status: OrderStatus::from_str(&order_status).unwrap(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CancelTraderOrderZkos {
    pub cancel_trader_order: CancelTraderOrder,
    pub msg: ZkosCancelMsg,
}
impl CancelTraderOrderZkos {
    pub fn new(
        cancel_trader_order: CancelTraderOrder,
        msg: ZkosCancelMsg,
    ) -> CancelTraderOrderZkos {
        CancelTraderOrderZkos {
            cancel_trader_order,
            msg,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }

    pub fn submit_order(order_msg: String) -> Result<GetCancelTraderOrderResponse, String> {
        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_msg },
            crate::relayer_rpcclient::method::Method::CancelTraderOrder,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(RELAYER_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetCancelTraderOrderResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };
        response_unwrap
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosCancelMsg {
    pub public_key: String, //This is Account hex address identified as public_key. Do not mistake it for public key of input
    pub signature: Signature, //quisquis signature  //canceltradeorder sign
}
impl ZkosCancelMsg {
    pub fn new(public_key: String, signature: Signature) -> ZkosCancelMsg {
        ZkosCancelMsg {
            public_key,
            signature,
        }
    }
    pub fn convert_cancel_to_query(&self) -> ZkosQueryMsg {
        ZkosQueryMsg::new(self.public_key.clone(), self.signature.clone())
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosQueryMsg {
    pub public_key: String, //This is Account hex address identified as public_key. Do not mistake it for public key of input
    pub signature: Signature, //quisquis signature  //canceltradeorder sign
}
impl ZkosQueryMsg {
    pub fn new(public_key: String, signature: Signature) -> ZkosQueryMsg {
        Self {
            public_key,
            signature,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTraderOrder {
    pub account_id: String,
    pub order_status: OrderStatus,
}
impl QueryTraderOrder {
    //new from values
    pub fn new(account_id: String, order_status: String) -> QueryTraderOrder {
        QueryTraderOrder {
            account_id,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTraderOrderZkos {
    pub query_trader_order: QueryTraderOrder,
    pub msg: ZkosQueryMsg,
}
impl QueryTraderOrderZkos {
    pub fn new(query_trader_order: QueryTraderOrder, msg: ZkosQueryMsg) -> QueryTraderOrderZkos {
        QueryTraderOrderZkos {
            query_trader_order,
            msg,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryLendOrder {
    pub account_id: String,
    pub order_status: OrderStatus,
}
impl QueryLendOrder {
    //new from values
    pub fn new(account_id: String, order_status: String) -> QueryLendOrder {
        QueryLendOrder {
            account_id,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryLendOrderZkos {
    pub query_lend_order: QueryLendOrder,
    pub msg: ZkosQueryMsg,
}
impl QueryLendOrderZkos {
    pub fn new(query_lend_order: QueryLendOrder, msg: ZkosQueryMsg) -> QueryLendOrderZkos {
        QueryLendOrderZkos {
            query_lend_order,
            msg,
        }
    }
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(zkos_data) => Ok(zkos_data),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TraderOrder {
    pub uuid: Uuid,
    pub account_id: String,
    pub position_type: PositionType,
    pub order_status: OrderStatus,
    pub order_type: OrderType,
    #[serde(deserialize_with = "as_f64")]
    pub entryprice: f64,
    #[serde(deserialize_with = "as_f64")]
    pub execution_price: f64,
    #[serde(deserialize_with = "as_f64")]
    pub positionsize: f64,
    #[serde(deserialize_with = "as_f64")]
    pub leverage: f64,
    #[serde(deserialize_with = "as_f64")]
    pub initial_margin: f64,
    #[serde(deserialize_with = "as_f64")]
    pub available_margin: f64,
    pub timestamp: String,
    #[serde(deserialize_with = "as_f64")]
    pub bankruptcy_price: f64,
    #[serde(deserialize_with = "as_f64")]
    pub bankruptcy_value: f64,
    #[serde(deserialize_with = "as_f64")]
    pub maintenance_margin: f64,
    #[serde(deserialize_with = "as_f64")]
    pub liquidation_price: f64,
    #[serde(deserialize_with = "as_f64")]
    pub unrealized_pnl: f64,
    #[serde(deserialize_with = "as_f64")]
    pub settlement_price: f64,
    pub entry_nonce: usize,
    pub exit_nonce: usize,
    pub entry_sequence: usize,
}
impl TraderOrder {
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(trader_order) => Ok(trader_order),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LendOrder {
    pub uuid: Uuid,
    pub account_id: String,
    #[serde(deserialize_with = "as_f64")]
    pub balance: f64,
    pub order_status: OrderStatus, //lend or settle
    pub order_type: OrderType,     // LEND
    pub entry_nonce: usize,        // change it to u256
    pub exit_nonce: usize,         // change it to u256
    #[serde(deserialize_with = "as_f64")]
    pub deposit: f64,
    #[serde(deserialize_with = "as_f64")]
    pub new_lend_state_amount: f64,
    pub timestamp: String,
    #[serde(deserialize_with = "as_f64")]
    pub npoolshare: f64,
    #[serde(deserialize_with = "as_f64")]
    pub nwithdraw: f64,
    #[serde(deserialize_with = "as_f64")]
    pub payment: f64,
    #[serde(deserialize_with = "as_f64")]
    pub tlv0: f64, //total locked value before lend tx
    #[serde(deserialize_with = "as_f64")]
    pub tps0: f64, // total poolshare before lend tx
    #[serde(deserialize_with = "as_f64")]
    pub tlv1: f64, // total locked value after lend tx
    #[serde(deserialize_with = "as_f64")]
    pub tps1: f64, // total poolshre value after lend tx
    #[serde(deserialize_with = "as_f64")]
    pub tlv2: f64, // total locked value before lend payment/settlement
    #[serde(deserialize_with = "as_f64")]
    pub tps2: f64, // total poolshare before lend payment/settlement
    #[serde(deserialize_with = "as_f64")]
    pub tlv3: f64, // total locked value after lend payment/settlement
    #[serde(deserialize_with = "as_f64")]
    pub tps3: f64, // total poolshare after lend payment/settlement
    pub entry_sequence: usize,
}

impl LendOrder {
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    pub fn decode_from_hex_string(hex_string: String) -> Result<Self, String> {
        let hex_decode = match hex::decode(hex_string) {
            Ok(bytes_data) => match bincode::deserialize(&bytes_data) {
                Ok(trader_order) => Ok(trader_order),
                Err(arg) => Err(format!("Error:{:?}", arg)),
            },
            Err(arg) => Err(format!("Error:{:?}", arg)),
        };
        hex_decode
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkos_settle_msg_decode() {
        let hex_str = "0100000001000000000000000000000001000000000000000000000000000000010101010000000000000000000000000000007b24b4202f440a02210a97259dcd3e5a5bce45965b0808738cf6d207001e282504c24eb9da0a517474ba8c91e3757330b4fdd5829585cbd015db96eca6cddf76334c19e99dd0670a63c32195b45a283911f7c88deaf694af627f2b6a075e8e816b8a0000000000000030636338316435393335336636373866663463643832383231303464376263626164383265633536313334323536356266383837336130306236383135303338333464653161653636383638323334343965346561313637653030643763623962633631323034366533353836316437363634363462376366353833346362663231363365313365353600010000000000000001000000010000002a000000000000003138323237323664346265336336623333623166333434633734333263626530343230333861663162388a000000000000003063633831643539333533663637386666346364383238323130346437626362616438326563353631333432353635626638383733613030623638313530333833346465316165363638363832333434396534656131363765303064376362396263363132303436653335383631643736363436346237636635383334636266323136336531336535360100000000000000960000000000000000000000000000000b2b0bd85855144bd22660963905f00d9da6702f35b8b9488b4b39f9785d5d09010400000000000000030000000100000064e4941300000000000000000000000000000000000000000000000000000000020000000100000000000000160000000000000000000000000000000b2b0bd85855144bd22660963905f00d9da6702f35b8b9488b4b39f9785d5d090300000001000000e1840100000000000000000000000000000000000000000000000000000000000300000001000000ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010000000001600000000000000060a0403000000060a0405000000060a0d0e1302020200000000010000000000000003000000000000003d107ff89a1f0387ca226522f82bca1fbf43059a200c49bdae998400bfe89ea52c92d3c5e02c98dc6b6f1f91cfd42e136d1d4f1de6bdb351b12be20f9535960c7c1b7c42e22f98283d98314b914cdbfc380ef2bb1c3e3a91685a05614fc4cf6da1010000000000000034ca9475efa2d661115967c60f72712666f676eb5707f47a680508996e02b62ea4e66dc5e5fcf60b18ab42c8e0e876163e3217770e859762cc72d69751b664090016db32b1514c0314f0f9058fafd6f89501358bd8fcea55216a411f31eec2037646d497898199bb4dea865c5eb38f72a0deb85ece868d7aeb7347ac7cb54f5aaa7ee3135c838c52fee6cd7de18e92ff0f52fc6a1268e5b963ba08fd1170cf2e52552b20b2b809553351a084229df6afeb06b432f14a503c5c546e3d4934fd4cc4144aa99ceb77c6bfa666a74a29ecad79e2662ded23377e2e33f6d6b65275531aa921f9fc2b8da92b37578c2f32eeb008f6f431703f225de8b55ca59e74f912c951f68f1249a1dc83bbe6c5317c9f0667fe24ddd3444a668823c1c3e65b8005c1948414032a65b59c1d0c6bc6c5753178f3503781a07ea9727b77ce2645210bc9f040b39e96fa56e23c674684266efb8c2dd64fe426f52c0fe503155c50d2091a59b2db95882fe2072a33f3d077bf3b9edea69bbaa2f74464f64250a21b680cd3f5923b855db53b7f79768e4113c141341a1d471b2be33463cdda2801d99f090100000000000000020000004000000000000000a2ec92b338f33fdf738878c95791e341cfa611768f2aab181098533431dbba0793a0c15bdc6d28b6e0f21f56f459316402b2dca053e93e9c3664f95fd75d560d01000000010000000000000019e7cef73aafdf03b2a2879f6877713e98138d00cc5f8065a0ebd62e9016de0301000000000000009e3fbd61072969550bdbc1d16b2ed195b4d4562f24b7f191c0a64f388c525a090000000000000000dfff85668f7a1f65c3adf805f9aaa12f617d734f0e49bb4cd52b71ab23030f0c01020000000100000000000000e40c00000000000000000000000000001d78c73228b12805922f396627dd010bf48cc2db54fcc8365ba67b67d5e8170b";

        let result = ZkosSettleMsg::decode_from_hex_string(hex_str.to_string());
        println!("result1: {:?}", result);

        let result2 = bincode::deserialize::<Transaction>(&hex::decode(hex_str).unwrap());
        println!("result2: {:?}", result2);
    }
}
