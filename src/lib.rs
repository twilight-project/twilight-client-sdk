#![allow(missing_docs)]
#![allow(non_snake_case)]

//! Twilight Client SDK with WASM support
//!
//! This crate provides client-side functionality for Twilight blockchain operations,
//! with specific optimizations and compatibility for WebAssembly deployment.

#[macro_use]
extern crate lazy_static;

pub extern crate quisquislib;
pub extern crate transaction;
pub extern crate zkschnorr;
pub extern crate zkvm;

pub mod programcontroller;
pub mod relayer;
pub mod relayer_types;
pub mod script;
pub mod transfer;
pub mod util;

// Re-export commonly used types for convenience
pub use programcontroller::ContractManager;
pub use relayer_types::*;
