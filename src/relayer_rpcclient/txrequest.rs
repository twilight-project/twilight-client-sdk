use super::id::Id;
use super::method::{Method, TransactionHashArgs, UtxoRequest};
// use curve25519_dalek::digest::Output;
use jsonrpc_core::response::{self, Failure, Output, Success};
use jsonrpc_core::Response as JsonRPCResponse;
use jsonrpc_core::Version;
use serde::{Deserialize, Serialize};
// use super::method::Method;
use reqwest::blocking::Response;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, USER_AGENT};
use serde_json::Error;
use transaction::Transaction;
// pub type TransactionStatusId = String;
use crate::relayer_rpcclient::method::ByteRec;
lazy_static! {
    pub static ref RELAYER_RPC_SERVER_URL: String = std::env::var("RELAYER_RPC_SERVER_URL")
        .expect("missing environment variable RELAYER_RPC_SERVER_URL");
    pub static ref PUBLIC_API_RPC_SERVER_URL: String = std::env::var("PUBLIC_API_RPC_SERVER_URL")
        .expect("missing environment variable PUBLIC_API_RPC_SERVER_URL");
}

fn construct_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("reqwest"));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcBody<T> {
    /// JSON-RPC version
    pub jsonrpc: Version,

    /// Identifier included in request
    pub id: Id,

    /// Request method
    pub method: Method,

    /// Request parameters (i.e. request object)
    pub params: T,
}

pub trait RpcRequest<T> {
    // fn remove(&mut self, order: T, cmd: RpcCommand) -> Result<T, std::io::Error>;
    fn new(request: T, method: Method) -> Self;

    fn new_with_id(id: Id, request: T, method: Method) -> Self;

    fn id(&self) -> &Id;

    fn params(&self) -> &T;

    fn get_method(&self) -> &Method;

    fn into_json(self) -> String;

    // fn send(self, url: String) -> Result<Response, reqwest::Error>;
    fn send(self, url: String) -> Result<RpcResponse<serde_json::Value>, reqwest::Error>;
    // fn response(resp: Result<Response, reqwest::Error>);
    // // -> Result<jsonrpc_core::Response, jsonrpc_core::Error>;
}

use std::fs::File;
use std::io::prelude::*;
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcResponse<T> {
    pub jsonrpc: Version,

    /// Identifier included in request
    pub id: jsonrpc_core::Id,
    pub result: Result<T, jsonrpc_core::Error>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resp {
    /// Protocol version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<Version>,
    /// Result
    pub result: String,
    /// Correlation id
    pub id: Id,
}

pub fn rpc_response(
    resp: Result<Response, reqwest::Error>,
) -> Result<RpcResponse<serde_json::Value>, reqwest::Error> {
    match resp {
        Ok(response) => {
            // if response.status().is_success() {
            let output: Output = serde_json::from_slice(&response.bytes().unwrap()).unwrap();
            let rpc_response = match output {
                Output::Success(s) => RpcResponse {
                    jsonrpc: s.jsonrpc.unwrap(),
                    id: s.id,
                    result: Ok(s.result),
                },
                Output::Failure(f) => RpcResponse {
                    jsonrpc: f.jsonrpc.unwrap(),
                    id: f.id,
                    result: Err(f.error),
                },
            };
            return Ok(rpc_response);

            // } else { };
        }
        Err(arg) => Err(arg),
    }
}

impl RpcRequest<ByteRec> for RpcBody<ByteRec> {
    fn new(request: ByteRec, method: Method) -> Self {
        Self::new_with_id(Id::uuid_v4(), request, method)
    }

    fn new_with_id(id: Id, request: ByteRec, method: Method) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            method: method,
            params: request,
        }
    }

    fn id(&self) -> &Id {
        &self.id
    }

    fn params(&self) -> &ByteRec {
        &self.params
    }
    fn into_json(self) -> String {
        let tx = serde_json::to_string(&self).unwrap();
        let mut file = File::create("foo.txt").unwrap();
        file.write_all(&serde_json::to_vec_pretty(&tx.clone()).unwrap())
            .unwrap();
        tx
    }

    fn get_method(&self) -> &Method {
        &self.method
    }

    fn send(
        self,
        url: std::string::String,
    ) -> Result<RpcResponse<serde_json::Value>, reqwest::Error> {
        match self.method {
            Method::CreateTraderOrder => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::CreateLendOrder => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::ExecuteTraderOrder => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::ExecuteLendOrder => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::CancelTraderOrder => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::trader_order_info => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::lend_order_info => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            _ => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
        }
    }
}

impl RpcRequest<TransactionHashArgs> for RpcBody<TransactionHashArgs> {
    fn new(request: TransactionHashArgs, method: Method) -> Self {
        Self::new_with_id(Id::uuid_v4(), request, method)
    }

    fn new_with_id(id: Id, request: TransactionHashArgs, method: Method) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            method: method,
            params: request,
        }
    }

    fn id(&self) -> &Id {
        &self.id
    }

    fn params(&self) -> &TransactionHashArgs {
        &self.params
    }
    fn into_json(self) -> String {
        let tx = serde_json::to_string(&self).unwrap();
        let mut file = File::create("foo.txt").unwrap();
        file.write_all(&serde_json::to_vec_pretty(&tx.clone()).unwrap())
            .unwrap();
        tx
    }

    fn get_method(&self) -> &Method {
        &self.method
    }

    fn send(
        self,
        url: std::string::String,
    ) -> Result<RpcResponse<serde_json::Value>, reqwest::Error> {
        match self.method {
            Method::transaction_hashes => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            _ => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
        }
    }
}

impl RpcRequest<Option<String>> for RpcBody<Option<String>> {
    fn new(request: Option<String>, method: Method) -> Self {
        Self::new_with_id(Id::uuid_v4(), request, method)
    }

    fn new_with_id(id: Id, request: Option<String>, method: Method) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            method: method,
            params: request,
        }
    }

    fn id(&self) -> &Id {
        &self.id
    }

    fn params(&self) -> &Option<String> {
        &self.params
    }
    fn into_json(self) -> String {
        let tx = serde_json::to_string(&self).unwrap();
        let mut file = File::create("foo.txt").unwrap();
        file.write_all(&serde_json::to_vec_pretty(&tx.clone()).unwrap())
            .unwrap();
        tx
    }

    fn get_method(&self) -> &Method {
        &self.method
    }

    fn send(
        self,
        url: std::string::String,
    ) -> Result<RpcResponse<serde_json::Value>, reqwest::Error> {
        match self.method {
            Method::btc_usd_price => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            _ => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
        }
    }
}

impl RpcRequest<UtxoRequest> for RpcBody<UtxoRequest> {
    fn new(request: UtxoRequest, method: Method) -> Self {
        Self::new_with_id(Id::uuid_v4(), request, method)
    }

    fn new_with_id(id: Id, request: UtxoRequest, method: Method) -> Self {
        Self {
            jsonrpc: Version::V2,
            id,
            method: method,
            params: request,
        }
    }

    fn id(&self) -> &Id {
        &self.id
    }

    fn params(&self) -> &UtxoRequest {
        &self.params
    }
    fn into_json(self) -> String {
        let tx = serde_json::to_string(&self).unwrap();
        let mut file = File::create("foo.txt").unwrap();
        file.write_all(&serde_json::to_vec_pretty(&tx.clone()).unwrap())
            .unwrap();
        tx
    }

    fn get_method(&self) -> &Method {
        &self.method
    }

    fn send(
        self,
        url: std::string::String,
    ) -> Result<RpcResponse<serde_json::Value>, reqwest::Error> {
        match self.method {
            Method::get_utxos_id => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::get_output => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            Method::get_utxos_detail => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
            _ => {
                let client = reqwest::blocking::Client::new();
                let clint_clone = client.clone();
                let res = clint_clone
                    .post(url)
                    .headers(construct_headers())
                    .body(self.into_json())
                    .send();

                return rpc_response(res);
            }
        }
    }
}

pub fn get_recent_price_from_relayer() -> Result<super::method::GetBTCPRice, String> {
    let tx_send: RpcBody<Option<String>> = RpcRequest::new(
        None,
        crate::relayer_rpcclient::method::Method::btc_usd_price,
    );
    let res: Result<
        crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
        reqwest::Error,
    > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

    let response_unwrap: Result<super::method::GetBTCPRice, String> = match res {
        Ok(rpc_response) => {
            match crate::relayer_rpcclient::method::GetBTCPRice::get_response(
                rpc_response,
            ) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    };
    response_unwrap
}

pub fn get_order_details_transactiion_hashes(
    address: String,
) -> Result<crate::relayer_rpcclient::method::GetTransactionHashResponse, String> {
    let tx_hash_arg1 = TransactionHashArgs::AccountId {
        id: address,
        status: None,
    };
    let tx_request: RpcBody<TransactionHashArgs> = RpcRequest::new(
        tx_hash_arg1,
        crate::relayer_rpcclient::method::Method::transaction_hashes,
    );
    let res: Result<
        crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
        reqwest::Error,
    > = tx_request.send(PUBLIC_API_RPC_SERVER_URL.clone());

    match res {
        Ok(rpc_response) => match crate::relayer_rpcclient::method::GetTransactionHashResponse::get_response(rpc_response) {
            Ok(response) => Ok(response),
            Err(arg) => Err(arg),
        },
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}

pub fn get_trader_order_info(
    msg: String,
) -> Result<crate::relayer_rpcclient::method::GetTraderOrderInfoResponse, String> {
    let tx_send: RpcBody<ByteRec> = RpcRequest::new(
        ByteRec { data: msg },
        crate::relayer_rpcclient::method::Method::trader_order_info,
    );
    let res: Result<
        crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
        reqwest::Error,
    > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

    match res {
            Ok(rpc_response) => match crate::relayer_rpcclient::method::GetTraderOrderInfoResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        }
}

#[cfg(test)]
mod test {
    use zkvm::IOType;

    use super::RELAYER_RPC_SERVER_URL;
    use crate::relayer_rpcclient::method::*;
    use crate::relayer_rpcclient::txrequest::{
        Resp, RpcBody, RpcRequest, PUBLIC_API_RPC_SERVER_URL,
    };
    use std::fs::File;
    use std::io::prelude::*;
    // cargo test -- --nocapture --test check_allOutputs_test --test-threads 5
    use crate::relayer_rpcclient::order_test_hex::*;
    use crate::chain::ZKOS_SERVER_URL;
    #[test]
    fn create_trader_order_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let order_string = trader_test_order();

        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: order_string },
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

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn query_trader_order_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let query_string = query_test_string();

        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: query_string },
            crate::relayer_rpcclient::method::Method::trader_order_info,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap: Result<GetTraderOrderInfoResponse, String> = match res {
            Ok(rpc_response) => match GetTraderOrderInfoResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn query_transaction_hash_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let tx_hash_arg1 = TransactionHashArgs::AccountId {
            id: "0cce46bfaf011e10a7ce54eb2ae0c1ced04150db04b640650d5d6b742eaf777e7c32444c7282842029780a82a715f6ecf39a627ece9e9ea5559aac0447714493675725dace".to_string(),
            status: None,
        };
        let _tx_hash_arg2: TransactionHashArgs = TransactionHashArgs::RequestId {
            id: "REQIDAEF51D3147D9FD400135A13DE7ADE176F171597F2D37936C0129BB11F05B6B68".to_string(),
            status: None,
        };

        let tx_send: RpcBody<TransactionHashArgs> = RpcRequest::new(
            tx_hash_arg1,
            crate::relayer_rpcclient::method::Method::transaction_hashes,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetTransactionHashResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn get_utxo_id_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let utxo_request_arg = UtxoRequest {
            address_or_id: "0c4846130acc477b3026998b495e880f4ee199ea1ad8955f6983c58a06b10b4a65fe34bdce04a9eed97518362577314dcb8bd5b0c15de0e0c7f0fba90c7e42a65b5d945ea4".to_string(),
            input_type: IOType::Coin,
        };

        let tx_send: RpcBody<UtxoRequest> = RpcRequest::new(
            utxo_request_arg,
            crate::relayer_rpcclient::method::Method::get_utxos_id,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(ZKOS_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetUtxoIdHex::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }
    #[test]
    fn get_utxo_output_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let utxo_request_arg = UtxoRequest {
            address_or_id: "8d14201652ddaf19b48d2274532671035d4db40e72e585354689a83b76f35ba407"
                .to_string(),
            input_type: IOType::Coin,
        };

        let tx_send: RpcBody<UtxoRequest> = RpcRequest::new(
            utxo_request_arg,
            crate::relayer_rpcclient::method::Method::get_output,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(ZKOS_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetUtxoOutput::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn query_btc_price_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let tx_send: RpcBody<Option<String>> = RpcRequest::new(
            None,
            crate::relayer_rpcclient::method::Method::btc_usd_price,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match GetBTCPRice::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }
    #[test]
    fn get_utxo_detail_test() {
        dotenv::dotenv().expect("Failed loading dotenv");

        let utxo_request_arg = UtxoRequest {
            address_or_id: "0c4846130acc477b3026998b495e880f4ee199ea1ad8955f6983c58a06b10b4a65fe34bdce04a9eed97518362577314dcb8bd5b0c15de0e0c7f0fba90c7e42a65b5d945ea4".to_string(),
            input_type: IOType::Coin,
        };

        let tx_send: RpcBody<UtxoRequest> = RpcRequest::new(
            utxo_request_arg,
            crate::relayer_rpcclient::method::Method::get_utxos_detail,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(ZKOS_SERVER_URL.clone());

        let response_unwrap = match res {
            Ok(rpc_response) => match UtxoDetailResponse::get_response(rpc_response) {
                Ok(response) => Ok(response),
                Err(arg) => Err(arg),
            },
            Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
        };

        println!("order response : {:#?}", response_unwrap);
        let mut file = File::create("foo_response.txt").unwrap();
        match response_unwrap {
            Ok(res) => {
                file.write_all(&serde_json::to_vec_pretty(&res).unwrap())
                    .unwrap();
            }
            Err(arg) => {
                file.write_all(&serde_json::to_vec_pretty(&arg).unwrap())
                    .unwrap();
            }
        }
    }
}
