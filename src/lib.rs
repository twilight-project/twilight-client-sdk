#![allow(missing_docs)]
#![allow(non_snake_case)]

//! ZkOS Client Wallet implementation.

pub extern crate zkos;
pub extern crate zkschnorr;

mod keys_management;
pub mod relayer;
pub mod relayer_types;
pub mod tx;
pub mod utxo_util;

//use rand::rngs::OsRng;
