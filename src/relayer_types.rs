use uuid::Uuid;
use zkvm::zkos_types::Input;

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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkosSettleMsg {
    pub input: Input,         //memo type input
    pub signature: Signature, //quisquis signature
}
impl ZkosSettleMsg {
    pub fn new(input: Input, signature: Signature) -> ZkosSettleMsg {
        ZkosSettleMsg { input, signature }
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
}
#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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
}
#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
}
