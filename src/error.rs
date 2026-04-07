//! Error types for the SMB2 library.

use crate::types::status::NtStatus;
use crate::types::Command;
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

    /// The server returned a non-success NTSTATUS.
    #[error("Protocol error: {status} during {command:?}")]
    Protocol {
        /// The NTSTATUS code from the response header.
        status: NtStatus,
        /// The command that triggered the error.
        command: Command,
    },

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
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
