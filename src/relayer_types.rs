use crate::relayer_rpcclient::method::*;
use crate::relayer_rpcclient::txrequest::RELAYER_RPC_SERVER_URL;
use crate::relayer_rpcclient::txrequest::{Resp, RpcBody, RpcRequest};
use quisquislib::accounts::SigmaProof;
use serde::{Deserialize, Serialize};
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
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OrderStatus {
    SETTLED,
    LENDED,
    LIQUIDATE,
    CANCELLED,
    PENDING, // change it to New
    FILLED,  //executed on price ticker
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
            _ => None,
        }
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

#[cfg(test)]
mod test {
    use address::{Address, Network};
    use curve25519_dalek::scalar::{self, Scalar};
    use quisquislib::{
        accounts::Account,
        elgamal::ElGamalCommitment,
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };
    use zkvm::{zkos_types::OutputCoin, Commitment, InputData, OutputData, Utxo, Witness};

    use crate::keys_management;

    use super::*;
    #[test]
    fn test_create_trader_order() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let create_trader_order: CreateTraderOrder = CreateTraderOrder::new(
            "account_id".to_string(),
            "LONG".to_string(),
            "MARKET".to_string(),
            10.0,
            10.0,
            10.0,
            "PENDING".to_string(),
            30000.0,
            30000.0,
        );
        // create input coin
        //create InputCoin and OutputMemo
        let mut rng = rand::thread_rng();
        let sk_in: RistrettoSecretKey = RistrettoSecretKey::random(&mut rng);
        let pk_in: RistrettoPublicKey = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);

        let add: Address = Address::standard_address(Network::default(), pk_in.clone());
        let rscalar: Scalar = Scalar::random(&mut rng);
        // create input coin
        let commit_in =
            ElGamalCommitment::generate_commitment(&pk_in, rscalar, Scalar::from(10u64));
        let enc_acc = Account::set_account(pk_in, commit_in);

        let coin = OutputCoin {
            encrypt: commit_in,
            owner: add.as_hex(),
        };
        let in_data: InputData = InputData::coin(Utxo::default(), coin, 0);
        let coin_in: Input = Input::coin(in_data.clone());

        //create first Commitment Witness
        let commit_1: Commitment = Commitment::blinded_with_factor(10u64, rscalar);
        let (_comit_1_value, _comit_1_blind) = commit_1.witness().unwrap();

        //create OutputMemo

        let out_memo = zkvm::zkos_types::OutputMemo {
            script_address: add.as_hex(),
            owner: add.as_hex(),
            commitment: commit_1.clone(),
            data: None,
            timebounds: 0,
        };
        let out_memo = Output::memo(OutputData::memo(out_memo));
        let memo_commitment_point = commit_1.to_point();
        // create InputCoin Witness
        let witness = Witness::ValueWitness(ValueWitness::create_value_witness(
            coin_in.clone(),
            sk_in,
            out_memo.clone(),
            enc_acc,
            pk_in.clone(),
            memo_commitment_point.clone(),
            10u64,
            rscalar,
        ));

        // verify the witness
        let value_wit = witness.to_value_witness().unwrap();
        let zkos_create_trader_order = ZkosCreateOrder::new(coin_in, out_memo, value_wit);
        let order_msg: CreateTraderOrderZkos = CreateTraderOrderZkos {
            create_trader_order: create_trader_order,
            input: zkos_create_trader_order,
        };

        println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }

    #[test]
    pub fn test_create_trader_order_broadcast_data() {
        dotenv::dotenv().expect("Failed loading dotenv");

        // // get private key from keys management
        // let sk = keys_management::load_wallet(
        //     "your_password_he".as_bytes(),
        //     "./wallet.txt".to_string(),
        //     "your_password_he".as_bytes(),
        // )
        // .unwrap();

        let seed =
        "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());
        let client_address = "0c3c8d3eb1eccbf8923e344b85de74faaa71cbbddcc0ce588ac1bc8fe83ad9be4c5cf205c86b01c43431060ba4d881d1eb29a511bea7bdf6cc3f02fc62246c434b0ac67f9e";
        // get pk from client address
        let address = Address::from_hex(&client_address, address::AddressType::default()).unwrap();
        let client_pk: RistrettoPublicKey = address.into();

        let path = "./relayerprogram.json";
        let programs = crate::programcontroller::ContractManager::import_program(path);
        let contract_address = programs
            .create_contract_address(Network::default())
            .unwrap();
        let input_coin =
            crate::chain::get_transaction_coin_input_from_address(client_address.to_string())
                .unwrap();

        // get encryption from input coin
        let enc_acc = input_coin.to_quisquis_account().unwrap();
        let key = enc_acc.decrypt_account_balance(&sk, Scalar::from(7000u64));
        println!("enc_acc:{:?}", key);
        let scalar_hex = "a11a387c557978a7b599a71af794bb4a85a0e89f897b094b32b8694420021408";
        let rscalar = crate::util::hex_to_scalar(scalar_hex.to_string()).unwrap();
        let output_memo = crate::util::create_output_memo_for_trader(
            contract_address,
            client_address.to_string(),
            7000,
            700000000,
            10,
            10000,
            scalar_hex.to_string(),
        )
        .unwrap();
        // get commitment from output memo
        let commitment = output_memo.as_output_data().get_commitment().unwrap();
        let memo_commitment_point = commitment.to_point();
        // create InputCoin Witness
        let witness = Witness::ValueWitness(ValueWitness::create_value_witness(
            input_coin.clone(),
            sk,
            output_memo.clone(),
            enc_acc,
            client_pk.clone(),
            memo_commitment_point.clone(),
            7000u64,
            rscalar,
        ));
        // verify the witness
        let value_wit = witness.to_value_witness().unwrap();
        //  let verify= value_wit.verify_value_witness(input, output, pubkey, enc_acc, commitment)
        let zkos_create_trader_order =
            ZkosCreateOrder::new(input_coin.clone(), output_memo.clone(), value_wit);

        let create_trader_order: CreateTraderOrder = CreateTraderOrder::new(
            "0x1234567890".to_string(),
            "LONG".to_string(),
            "MARKET".to_string(),
            10.0,
            7000.0,
            0.0,
            "PENDING".to_string(),
            10000.0,
            0.0,
        );

        let order_msg: CreateTraderOrderZkos = CreateTraderOrderZkos {
            create_trader_order: create_trader_order,
            input: zkos_create_trader_order,
        };

        println!("order_hex: {:?}", order_msg.encode_as_hex_string());
    }
}
