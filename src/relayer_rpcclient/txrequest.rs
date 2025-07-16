//! JSON-RPC request and response handling for the Twilight Relayer client.
//!
//! This module provides the infrastructure for constructing and sending JSON-RPC
//! requests to the relayer service, handling responses, and managing HTTP communication.

use super::id::Id;
use super::method::{Method, TransactionHashArgs, UtxoRequest};
// use curve25519_dalek::digest::Output;
use jsonrpc_core::response::{Failure, Output, Success};
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
    /// The URL of the relayer RPC server, loaded from the `RELAYER_RPC_SERVER_URL` environment variable.
    ///
    /// # Panics
    /// Panics if the `RELAYER_RPC_SERVER_URL` environment variable is not set at runtime.
    pub static ref RELAYER_RPC_SERVER_URL: String = std::env::var("RELAYER_RPC_SERVER_URL")
        .expect("missing environment variable RELAYER_RPC_SERVER_URL");
}

/// Constructs standard HTTP headers for JSON-RPC requests.
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

/// Represents a JSON-RPC request body.
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

/// Trait defining the interface for JSON-RPC requests.
pub trait RpcRequest<T> {
    /// Creates a new RPC request with a random UUID.
    fn new(request: T, method: Method) -> Self;

    /// Creates a new RPC request with a specific ID.
    fn new_with_id(id: Id, request: T, method: Method) -> Self;

    /// Returns the request ID.
    fn id(&self) -> &Id;

    /// Returns the request parameters.
    fn params(&self) -> &T;

    /// Returns the request method.
    fn get_method(&self) -> &Method;

    /// Converts the request to a JSON string.
    fn into_json(self) -> String;

    /// Sends the request to the specified URL.
    fn send(self, url: String) -> Result<RpcResponse<serde_json::Value>, reqwest::Error>;
}

use std::fs::File;
use std::io::prelude::*;

/// Represents a JSON-RPC response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcResponse<T> {
    pub jsonrpc: Version,

    /// Identifier included in request
    pub id: jsonrpc_core::Id,
    pub result: Result<T, jsonrpc_core::Error>,
}

/// Legacy response structure (kept for compatibility).
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

/// Converts a raw HTTP response to a structured RPC response.
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

#[cfg(test)]
mod test {
    use zkvm::IOType;

    use super::RELAYER_RPC_SERVER_URL;
    use crate::relayer_rpcclient::method::*;
    use crate::relayer_rpcclient::txrequest::{Resp, RpcBody, RpcRequest};
    use crate::util::ZKOS_SERVER_URL;
    use std::fs::File;
    use std::io::prelude::*;
    // cargo test -- --nocapture --test check_allOutputs_test --test-threads 5

    // Some test functions helpers
    pub fn trader_test_order() -> String {
        "0a000000000000006163636f756e745f6964010000000100000000000000000024400000000000000040000000000000004004000000cdcccccc0c32c9403d0ad7a300b3e5400000000000000000000000000000000000000000000000000000000000000000000000000000000000909df156fd793e9ce9d01ce436b057acf845f6ebb47fec7ea50689e631663b79920e3ebfe8e435b5d9a673386de4bf60aea206762b0c3cf442e4c5e310abfe108a000000000000003063373039613931393431643538383466346530633634333966656231626565363362656639316262653162623765633938343235303065383037633038373837393661666231313634623430666537373539383734643639646266306461643732623761336466396366643662666363363832363466386364633736396337366566383137393065360001000000010000002c0000000000000022343262343334633132303965363430336133653035666363636132373935633865626262383135303830228a0000000000000030633730396139313934316435383834663465306336343339666562316265653633626566393162626531626237656339383432353030653830376330383738373936616662313136346234306665373735393837346436396462663064616437326237613364663963666436626663633638323634663863646337363963373665663831373930653601000000000000000a000000000000000000000000000000da992544fefd07d04b94f861d42859931c1eae68f605ec77505ca8fc36645e0d0101000000000000000200000001000000000000000a000000000000000000000000000000da992544fefd07d04b94f861d42859931c1eae68f605ec77505ca8fc36645e0d000000004000000000000000f60e2588bfe31c52ce1208119c41a18194bd78865f957c0e8289507e290c5d12b43970f1b0a7a5b0450a736efd354c6a7f13ba513063d179313a893138863e03010000000100000000000000a3ecc71aa29700c33dc668843f50dba922e80fb4d0d24d96d34c6debd602ac0d010000000000000071731360a428f00b8e91044974695885f34ba394a725a14ccaeff3b8af43a70d000000000000000052364995ca3c5a80c84204bfb6e51170086d3d9ae33e8855eea215c25dbcce06".to_string()
    }
    pub fn lend_test_order() -> String {
        "".to_string()
    }
    pub fn trader_test_settle() -> String {
        "".to_string()
    }
    pub fn lend_test_settle() -> String {
        "".to_string()
    }

    pub fn query_test_string() -> String {
        "8a00000000000000306335343261666462626431633831386235393166643464386163393264306335323462613664666164366637363032613937393438666661343433393731643564343832306165333961303262316136653133313065323137633336333638383635613466643831343437373939323464313934636133393830613461386332313031633333396134040000008a0000000000000030633534326166646262643163383138623539316664346438616339326430633532346261366466616436663736303261393739343866666134343339373164356434383230616533396130326231613665313331306532313763333633363838363561346664383134343737393932346431393463613339383061346138633231303163333339613440000000000000008c407fb9986d991044c91359a26989a1140cd6e7230e505a09726f993949042e7c43936e9e550abdb102a41ac250538eeac1dcc245873a158e3ec058bbd4b80c".to_string()
    }
    #[test]
    fn create_trader_order_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");

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
        dotenvy::dotenv().expect("Failed loading dotenv");
        let PUBLIC_API_RPC_SERVER_URL = std::env::var("PUBLIC_API_RPC_SERVER_URL")
            .expect("missing environment variable PUBLIC_API_RPC_SERVER_URL");
        let query_string = query_test_string();

        let tx_send: RpcBody<ByteRec> = RpcRequest::new(
            ByteRec { data: query_string },
            crate::relayer_rpcclient::method::Method::trader_order_info,
        );
        let res: Result<
            crate::relayer_rpcclient::txrequest::RpcResponse<serde_json::Value>,
            reqwest::Error,
        > = tx_send.send(PUBLIC_API_RPC_SERVER_URL.clone());

        let response_unwrap = match res {
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
        dotenvy::dotenv().expect("Failed loading dotenv");
        let PUBLIC_API_RPC_SERVER_URL = std::env::var("PUBLIC_API_RPC_SERVER_URL")
            .expect("missing environment variable PUBLIC_API_RPC_SERVER_URL");
        let tx_hash_arg1 = TransactionHashArgs::AccountId {
            id: "0cce46bfaf011e10a7ce54eb2ae0c1ced04150db04b640650d5d6b742eaf777e7c32444c7282842029780a82a715f6ecf39a627ece9e9ea5559aac0447714493675725dace".to_string(),
            status: None,
        };
        let _tx_hash_arg2 = TransactionHashArgs::RequestId {
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
        dotenvy::dotenv().expect("Failed loading dotenv");

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
    fn get_utxos_detail_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");

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

    #[test]
    fn get_utxo_output_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");

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
        dotenvy::dotenv().expect("Failed loading dotenv");
        let PUBLIC_API_RPC_SERVER_URL = std::env::var("PUBLIC_API_RPC_SERVER_URL")
            .expect("missing environment variable PUBLIC_API_RPC_SERVER_URL");
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
}
