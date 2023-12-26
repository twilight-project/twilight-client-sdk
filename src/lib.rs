#![allow(missing_docs)]
#![allow(non_snake_case)]

//! ZkOS Client Wallet implementation.

pub extern crate quisquislib;
pub extern crate transaction;
pub extern crate transactionapi;
pub extern crate zkschnorr;
pub extern crate zkvm;

mod keys_management;
pub mod relayer;
pub mod relayer_types;
pub mod script;
pub mod transfer;
pub mod utxo_util;

//use rand::rngs::OsRng;
