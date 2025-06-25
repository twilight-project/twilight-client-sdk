use crate::relayer_rpcclient::method::*;
use crate::relayer_rpcclient::txrequest::RELAYER_RPC_SERVER_URL;
use crate::relayer_rpcclient::txrequest::{Resp, RpcBody, RpcRequest};
use curve25519_dalek::scalar::Scalar;
use quisquislib::accounts::SigmaProof;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_f64;
use transaction::Transaction;
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
    FilledUpdated,
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
            "FilledUpdated" => Some(OrderStatus::FilledUpdated),
            _ => None,
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
    FilledUpdated,
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
            "FilledUpdated" => Some(RequestStatus::FilledUpdated),
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
