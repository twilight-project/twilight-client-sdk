//! JSON-RPC version management for the Twilight Relayer client.
//!
//! This module provides version validation and compatibility checking for JSON-RPC
//! communication with the relayer service. It ensures that the client and server
//! are using compatible versions of the JSON-RPC protocol.

use core::{
    fmt::{self, Display},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use std::io::Error;
// use crate::prelude::*;

/// The currently supported JSON-RPC version.
///
/// This constant defines the version of JSON-RPC that this client implementation
/// supports. All RPC requests and responses must conform to this version.
const SUPPORTED_VERSION: &str = "2.0";

/// Represents a JSON-RPC protocol version.
///
/// This struct wraps a version string and provides methods to validate
/// compatibility with the supported version. It implements serialization
/// and deserialization for use in RPC messages. 
/// TODO(tarcieri): add restrictions/validations on these formats? Use an `enum`?
///
/// # Examples
///
/// ```rust
/// use twilight_client_sdk::relayer_rpcclient::version::Version;
///
/// let version = Version::current();
/// assert!(version.is_supported());
///
/// let unsupported = Version::from_str("1.0").unwrap();
/// assert!(!unsupported.is_supported());
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct Version(String);

impl Version {
    /// Returns the currently supported JSON-RPC version.
    ///
    /// This method creates a new `Version` instance with the supported
    /// version string.
    ///
    /// # Returns
    /// A `Version` instance representing the supported JSON-RPC version.
    pub fn current() -> Self {
        Version(SUPPORTED_VERSION.to_owned())
    }

    /// Checks if this version is supported by the client.
    ///
    /// Compares the version string against the supported version constant.
    ///
    /// # Returns
    /// `true` if the version is supported, `false` otherwise.
    pub fn is_supported(&self) -> bool {
        self.0.eq(SUPPORTED_VERSION)
    }

    /// Validates that this version is supported, returning an error if not.
    ///
    /// This method is useful for early validation of RPC responses or
    /// configuration settings to ensure compatibility.
    ///
    /// # Returns
    /// `Ok(())` if the version is supported, or an `Error` with details
    /// about the unsupported version.
    ///
    /// # Errors
    /// Returns an error if the version is not supported, including both
    /// the received version and the supported version in the error message.
    pub fn ensure_supported(&self) -> Result<(), Error> {
        if self.is_supported() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "Unsupported RPC version"))
        }
    }
}

impl Display for Version {
    /// Formats the version as a string.
    ///
    /// This allows the `Version` to be used in string formatting contexts.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Version {
    type Err = Error;

    /// Creates a `Version` from a string.
    ///
    /// This implementation always succeeds, creating a `Version` with the
    /// provided string. No validation is performed during parsing - use
    /// `is_supported()` or `ensure_supported()` to check compatibility.
    ///
    /// # Parameters
    /// - `s`: The version string to parse.
    ///
    /// # Returns
    /// A `Result` containing the `Version` on success, or an `Error` on failure.
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(Version(s.to_owned()))
    }
}
