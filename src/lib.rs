#![allow(missing_docs)]
#![allow(non_snake_case)]

//! Twilight Client SDK - A comprehensive Rust library for building applications on the Twilight.
//!
//! This SDK provides a complete set of tools for interacting with the Twilight ecosystem,
//! including wallet management, transaction creation, smart contract deployment, and
//! integration with the Twilight Relayer for trading and lending operations.
//!
//! # Key Features
//!
//! - **Wallet Management**: Secure creation and management of encrypted wallet files
//! - **Transaction Building**: Support for private transfers, Quisquis transactions, and smart contract calls
//! - **Smart Contract Deployment**: Tools for deploying and interacting with ZkVM-based contracts
//! - **Relayer Integration**: Complete API for trading and lending operations
//! - **Blockchain Interaction**: RPC client for fetching UTXOs and broadcasting transactions
//!
//! # Quick Start
//!
//! ```rust
//! use twilight_client_sdk::keys_management;
//! use twilight_client_sdk::transfer;
//! use twilight_client_sdk::relayer;
//!
//! // Initialize a wallet
//! let wallet = keys_management::init_wallet("wallet.dat", "password123", None)?;
//!
//! // Create a private transfer
//! let tx_hex = transfer::create_private_transfer_tx_single(
//!     secret_key,
//!     sender_input,
//!     receiver_address,
//!     amount,
//!     false,
//!     updated_balance,
//!     fee,
//! );
//! ```
//!
//! # Module Overview
//!
//! - [`keys_management`] - Wallet creation, loading, and key management
//! - [`transfer`] - Transaction creation for private transfers and Quisquis operations
//! - [`relayer`] - High-level API for trading and lending operations
//! - [`script`] - Smart contract deployment and interaction
//! - [`chain`] - Blockchain RPC client for fetching data and broadcasting transactions
//! - [`util`] - Utility functions for data conversion and transaction building
//! - [`programcontroller`] - ZkVM program management and Merkle proof generation
//! - [`relayer_types`] - Data structures for relayer API communication
//! - [`relayer_rpcclient`] - Low-level RPC client for relayer communication

#[macro_use]
extern crate lazy_static;
// #[macro_use]
extern crate diesel;
pub extern crate quisquislib;
pub extern crate transaction;
pub extern crate transactionapi;
pub extern crate zkschnorr;
pub extern crate zkvm;

/// Blockchain interaction and RPC client functionality.
pub mod chain;

// pub mod db; // Temporarily disabled due to compilation issues

/// Wallet creation, loading, and key management operations.
pub mod keys_management;

/// ZkVM program management and smart contract utilities.
pub mod programcontroller;

/// High-level API for trading and lending operations via the Twilight Relayer.
pub mod relayer;

/// Low-level RPC client implementation for relayer communication.
pub mod relayer_rpcclient;

/// Data structures and types for relayer API communication.
pub mod relayer_types;

/// Smart contract deployment and script transaction creation.
pub mod script;

/// Transaction creation for private transfers and Quisquis operations.
pub mod transfer;

/// Utility functions for data conversion and transaction building.
pub mod util;

pub mod agent;
pub mod db_ops;
pub mod models;
pub mod schema;
mod test;
