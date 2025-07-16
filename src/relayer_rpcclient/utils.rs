//! Utility functions for the Twilight Relayer RPC client.
//!
//! This module provides helper functions used throughout the RPC client implementation.

use rand::RngCore;
//use getrandom::getrandom;
use uuid::Uuid;

// use crate::prelude::*;

/// Generates a random UUID v4 string.
///
/// This function creates a new UUID using the system's random number generator
/// and returns it as a formatted string.
///
/// # Returns
/// A string representation of a randomly generated UUID v4.
///
/// # Panics
/// Panics if random number generation fails.
pub fn uuid_str() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);

    let uuid = Uuid::new_v4();
    uuid.to_string()
}
