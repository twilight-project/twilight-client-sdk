//! Defines the data structures and types used for communication with the Twilight Relayer.
//!
//! This module contains all the necessary request and response types for creating,
//! executing, and querying trade and lend orders. It includes various enums for
//! categorizing orders (e.g., `OrderType`, `PositionType`, `OrderStatus`) and
//! structs that wrap the zero-knowledge components (`ZkosCreateOrder`, `ZkosSettleMsg`)
//! with the order metadata. These types are serialized and sent to the relayer's
//! private API endpoints.

use crate::relayer_rpcclient::method::*;
use crate::relayer_rpcclient::txrequest::RELAYER_RPC_SERVER_URL;
use crate::relayer_rpcclient::txrequest::{RpcBody, RpcRequest};
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

/// The type of transaction being submitted, distinguishing between trading and lending.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TXType {
    /// A standard perpetual contract trade order.
    ORDERTX,
    /// A lending or borrowing order for the DeFi pool.
    LENDTX,
}

impl TXType {
    /// Creates a `TXType` from a string slice.
    pub fn from_str(s: &str) -> Option<TXType> {
        match s {
            "ORDERTX" => Some(TXType::ORDERTX),
            "LENDTX" => Some(TXType::LENDTX),
            _ => None,
        }
    }
}

/// The execution type of an order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OrderType {
    /// A limit order, which executes at a specified price or better.
    LIMIT,
    /// A market order, which executes immediately at the current market price.
    MARKET,
    /// A dark order, not currently implemented.
    DARK,
    /// A lend order for the lending pool.
    LEND,
}
impl OrderType {
    /// Creates an `OrderType` from a string slice.
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

/// The direction of a trading position.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PositionType {
    /// A long position, betting on a price increase.
    LONG,
    /// A short position, betting on a price decrease.
    SHORT,
}
impl PositionType {
    /// Creates a `PositionType` from a string slice.
    pub fn from_str(s: &str) -> Option<PositionType> {
        match s {
            "LONG" => Some(PositionType::LONG),
            "SHORT" => Some(PositionType::SHORT),
            _ => None,
        }
    }

    /// Converts the position type to a scalar value for use in ZK proofs.
    /// `LONG` is -1, `SHORT` is 1.
    pub fn to_scalar(&self) -> Scalar {
        match self {
            PositionType::LONG => Scalar::zero() - Scalar::from(1u64),
            PositionType::SHORT => Scalar::from(1u64),
        }
    }

    /// Converts the position type back to its string representation.
    pub fn to_str(&self) -> String {
        match self {
            PositionType::LONG => "LONG".to_string(),
            PositionType::SHORT => "SHORT".to_string(),
        }
    }
}

/// Represents the various states an order can be in throughout its lifecycle.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OrderStatus {
    /// The order has been successfully settled.
    SETTLED,
    /// The lend order is active in the pool.
    LENDED,
    /// The position has been liquidated.
    LIQUIDATE,
    /// The order has been cancelled.
    CANCELLED,
    /// The order has been submitted but not yet processed.
    PENDING,
    /// The order has been matched and executed by the engine.
    FILLED,
    /// The order was rejected as a duplicate.
    DuplicateOrder,
    /// An error occurred with the UTXO.
    UtxoError,
    /// A generic error occurred.
    Error,
    /// The relayer received no response from the chain.
    NoResponseFromChain,
    /// The transaction was rejected by the chain.
    RejectedFromChain,
    /// An error occurred during bincode serialization/deserialization.
    BincodeError,
    /// An error occurred during hex encoding/decoding.
    HexCodeError,
    /// A generic serialization error.
    SerializationError,
    /// The order was submitted successfully to the relayer.
    RequestSubmitted,
    /// The requested order could not be found.
    OrderNotFound,
    /// The order has been filled and its state updated, awaiting settlement.
    FilledUpdated,
}
impl OrderStatus {
    /// Creates an `OrderStatus` from a string slice.
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

/// Represents the status of a request made to the relayer.
/// Note: This is largely identical to `OrderStatus` and could potentially be consolidated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RequestStatus {
    SETTLED,
    LENDED,
    LIQUIDATE,
    CANCELLED,
    PENDING,
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
    /// Creates a `RequestStatus` from a string slice.
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

/// A structure that pairs a ZkOS transaction with its corresponding output memo.
/// This is used internally before the final order message is constructed.
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

/// The core zero-knowledge component of a `create` order message.
///
/// This struct contains the input coin, the output memo, and the cryptographic
/// signature and proof required to validate the order request without revealing
/// sensitive information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkosCreateOrder {
    /// The coin `Input` being spent to fund the order.
    pub input: Input,
    /// The `Output` memo containing the order's public/private data commitments.
    pub output: Output,
    /// The zkSchnorr signature proving ownership of the input.
    pub signature: Signature,
    /// This is a proof of the same value locked between the input and output.
    pub proof: SigmaProof,
}
impl ZkosCreateOrder {
    /// Creates a new `ZkosCreateOrder` from an input, output, and a `ValueWitness`.
    /// The witness provides the necessary signature and proof.
    pub fn new(input: Input, output: Output, vw: ValueWitness) -> Self {
        Self {
            input,
            output,
            signature: vw.get_signature().clone(),
            proof: vw.get_value_proof().clone(),
        }
    }
    /// Encodes the struct into a hex string for transport.
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }
    /// Decodes a `ZkosCreateOrder` from a hex string.
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

/// The metadata payload for creating a new trader order.
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
    /// Creates a new `CreateTraderOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if the string values for `position_type`, `order_type`, or `order_status` are invalid.
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

/// The complete message for submitting a new trader order.
///
/// This struct combines the order metadata (`CreateTraderOrder`) with its
/// corresponding zero-knowledge proof components (`ZkosCreateOrder`).
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

    /// Encodes the full order message into a hex string.
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    /// Decodes the full order message from a hex string.
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

    /// Submits the hex-encoded order message to the relayer via RPC.
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

/// The metadata payload for creating a new lend order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CreateLendOrder {
    pub account_id: String,
    pub balance: f64,
    pub order_type: OrderType,
    pub order_status: OrderStatus,
    pub deposit: f64,
}
impl CreateLendOrder {
    /// Creates a new `CreateLendOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_type` or `order_status` strings are invalid.
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

/// The complete message for submitting a new lend order.
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
    /// Encodes the full lend order message into a hex string.
    pub fn encode_as_hex_string(&self) -> String {
        let byt = bincode::serialize(&self).unwrap();
        hex::encode(&byt)
    }

    /// Decodes the full lend order message from a hex string.
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

    /// Submits the hex-encoded lend order message to the relayer via RPC.
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

/// A client-side representation of a trader order that includes the full `Transaction`.
/// This is an alternative structure that may be used in different client flows.
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

/// The zero-knowledge component for a settlement or execution message.
///
/// It contains the output memo from the original order and a signature to authorize the action.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosSettleMsg {
    /// The `Output` memo from the original `create` order transaction.
    pub output: Output,
    /// The zkSchnorr signature authorizing this settlement.
    pub signature: Signature,
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

/// The metadata payload for settling a trader order.
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
    /// Creates a new `ExecuteTraderOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_type` or `order_status` strings are invalid.
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

/// The complete message for settling a trader order.
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

    /// Submits the hex-encoded settlement message to the relayer via RPC.
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

/// The metadata payload for settling a lend order (e.g., withdrawing funds).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExecuteLendOrder {
    pub account_id: String,
    pub uuid: Uuid,
    pub order_type: OrderType,
    /// The percentage amount to withdraw from the lending position.
    pub settle_withdraw: f64,
    pub order_status: OrderStatus,
    /// The pool share price at the time of withdrawal.
    pub poolshare_price: f64,
}
impl ExecuteLendOrder {
    /// Creates a new `ExecuteLendOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_type` or `order_status` strings are invalid.
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

/// The complete message for settling a lend order.
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

    /// Submits the hex-encoded lend settlement message to the relayer via RPC.
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

/// The metadata payload for cancelling a trader order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CancelTraderOrder {
    pub account_id: String,
    pub uuid: Uuid,
    pub order_type: OrderType,
    pub order_status: OrderStatus,
}
impl CancelTraderOrder {
    /// Creates a new `CancelTraderOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_type` or `order_status` strings are invalid.
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

/// The complete message for cancelling a trader order.
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

    /// Submits the hex-encoded cancellation message to the relayer via RPC.
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

/// The zero-knowledge component for a cancellation message.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosCancelMsg {
    /// The user's hex-encoded account address.
    pub public_key: String,
    /// A zkSchnorr signature over the `CancelTraderOrder` message, authorizing the cancellation.
    pub signature: Signature,
}
impl ZkosCancelMsg {
    pub fn new(public_key: String, signature: Signature) -> ZkosCancelMsg {
        ZkosCancelMsg {
            public_key,
            signature,
        }
    }
    /// Converts a `ZkosCancelMsg` into a `ZkosQueryMsg`, as they are structurally identical.
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

/// The zero-knowledge component for a query message.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ZkosQueryMsg {
    /// The user's hex-encoded account address.
    pub public_key: String,
    /// A signature over the query data, authorizing the request.
    pub signature: Signature,
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

/// The metadata payload for querying a trader order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTraderOrder {
    pub account_id: String,
    pub order_status: OrderStatus,
}
impl QueryTraderOrder {
    /// Creates a new `QueryTraderOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_status` string is invalid.
    pub fn new(account_id: String, order_status: String) -> QueryTraderOrder {
        QueryTraderOrder {
            account_id,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
        }
    }
}

/// The complete message for querying a trader order.
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

/// The metadata payload for querying a lend order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryLendOrder {
    pub account_id: String,
    pub order_status: OrderStatus,
}
impl QueryLendOrder {
    /// Creates a new `QueryLendOrder` instance from raw values.
    ///
    /// # Panics
    /// Panics if `order_status` string is invalid.
    pub fn new(account_id: String, order_status: String) -> QueryLendOrder {
        QueryLendOrder {
            account_id,
            order_status: OrderStatus::from_str(&order_status).unwrap(),
        }
    }
}

/// The complete message for querying a lend order.
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

/// Represents the full state of a trader order as returned by the relayer's query endpoints.
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
    #[serde(deserialize_with = "as_f64")]
    pub fee_filled: f64,
    #[serde(deserialize_with = "as_f64")]
    pub fee_settled: f64,
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

/// Represents the full state of a lend order as returned by the relayer's query endpoints.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LendOrder {
    pub uuid: Uuid,
    pub account_id: String,
    #[serde(deserialize_with = "as_f64")]
    pub balance: f64,
    pub order_status: OrderStatus,
    pub order_type: OrderType,
    pub entry_nonce: usize,
    pub exit_nonce: usize,
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
    /// Total locked value before this lend transaction.
    #[serde(deserialize_with = "as_f64")]
    pub tlv0: f64,
    /// Total pool shares before this lend transaction.
    #[serde(deserialize_with = "as_f64")]
    pub tps0: f64,
    /// Total locked value after this lend transaction.
    #[serde(deserialize_with = "as_f64")]
    pub tlv1: f64,
    /// Total pool shares after this lend transaction.
    #[serde(deserialize_with = "as_f64")]
    pub tps1: f64,
    /// Total locked value before a lend payment/settlement.
    #[serde(deserialize_with = "as_f64")]
    pub tlv2: f64,
    /// Total pool shares before a lend payment/settlement.
    #[serde(deserialize_with = "as_f64")]
    pub tps2: f64,
    /// Total locked value after a lend payment/settlement.
    #[serde(deserialize_with = "as_f64")]
    pub tlv3: f64,
    /// Total pool shares after a lend payment/settlement.
    #[serde(deserialize_with = "as_f64")]
    pub tps3: f64,
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

/// Represents a transaction hash record, linking an order to its on-chain transaction.
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
