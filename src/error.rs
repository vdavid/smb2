//! Error types for the SMB2 library.

use thiserror::Error;

/// Top-level error type for SMB2 operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The data is malformed or does not match the expected format.
    #[error("Invalid data: {message}")]
    InvalidData {
        /// Description of what went wrong.
        message: String,
    },
}

impl Error {
    /// Create an `InvalidData` error with the given message.
    pub fn invalid_data(msg: impl Into<String>) -> Self {
        Error::InvalidData {
            message: msg.into(),
        }
    }
}

/// A `Result` type alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
