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

    /// Authentication failed.
    #[error("Authentication failed: {message}")]
    Auth {
        /// Description of what went wrong.
        message: String,
    },

    /// An I/O or transport error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The operation timed out.
    #[error("Operation timed out")]
    Timeout,

    /// The connection was lost.
    #[error("Disconnected from server")]
    Disconnected,

    /// The path requires DFS referral resolution.
    ///
    /// The server returned `STATUS_PATH_NOT_COVERED`, meaning this path
    /// lives on a different server via DFS. The caller can query for a
    /// referral or display a helpful message.
    #[error("DFS referral required for path: {path}")]
    DfsReferralRequired {
        /// The path that needs DFS resolution.
        path: String,
    },

    /// The operation was cancelled by the caller (via progress callback).
    #[error("Operation cancelled")]
    Cancelled,

    /// The session expired and reauthentication failed.
    ///
    /// The pipeline normally handles `STATUS_NETWORK_SESSION_EXPIRED`
    /// transparently by reauthenticating. This error surfaces only
    /// when reauthentication itself fails.
    #[error("Session expired and reauthentication failed")]
    SessionExpired,
}

impl Error {
    /// Create an `InvalidData` error with the given message.
    pub fn invalid_data(msg: impl Into<String>) -> Self {
        Error::InvalidData {
            message: msg.into(),
        }
    }

    /// Returns `true` if this error is potentially transient and
    /// the operation could succeed on retry.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Timeout
                | Error::Disconnected
                | Error::Protocol {
                    status: NtStatus::INSUFFICIENT_RESOURCES,
                    ..
                }
                | Error::Protocol {
                    status: NtStatus::INSUFF_SERVER_RESOURCES,
                    ..
                }
        )
    }

    /// Returns the NTSTATUS code if this is a protocol error.
    pub fn status(&self) -> Option<NtStatus> {
        match self {
            Error::Protocol { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// High-level error classification.
///
/// Maps protocol-level NTSTATUS codes and other errors into categories
/// that consumers can match on without understanding SMB internals.
///
/// ```no_run
/// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
/// use smb2::ErrorKind;
///
/// match client.read_file(&share, "photo.jpg").await {
///     Ok(data) => println!("read {} bytes", data.len()),
///     Err(e) => match e.kind() {
///         ErrorKind::NotFound => println!("file doesn't exist"),
///         ErrorKind::AccessDenied => println!("no permission"),
///         ErrorKind::SigningRequired => println!("server requires signing, use credentials"),
///         ErrorKind::AuthRequired => println!("server requires authentication"),
///         ErrorKind::SharingViolation => println!("file is in use by another client"),
///         ErrorKind::DiskFull => println!("volume is full"),
///         ErrorKind::ConnectionLost => { client.reconnect().await?; }
///         _ => return Err(e),
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The server requires authentication (guest/anonymous not allowed).
    AuthRequired,
    /// The server requires message signing (guest sessions are unsigned).
    SigningRequired,
    /// Permission denied (valid credentials, but no access to this resource).
    AccessDenied,
    /// The file, directory, or share was not found.
    NotFound,
    /// The file is in use by another client.
    SharingViolation,
    /// The volume is full (write failed).
    DiskFull,
    /// The network connection was lost.
    ConnectionLost,
    /// The operation timed out.
    TimedOut,
    /// The operation was cancelled by the caller.
    Cancelled,
    /// The session expired (call `reconnect()`).
    SessionExpired,
    /// The path requires DFS referral resolution.
    DfsReferral,
    /// Invalid data or malformed response.
    InvalidData,
    /// A protocol error not covered by other variants.
    ///
    /// Use [`Error::status()`] to get the raw NTSTATUS code.
    Other,
}

impl Error {
    /// Classify this error into a high-level category.
    ///
    /// Consumers can match on [`ErrorKind`] without understanding raw
    /// NTSTATUS codes. For the underlying status code, use [`status()`](Self::status).
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::InvalidData { .. } => ErrorKind::InvalidData,
            Error::Auth { .. } => ErrorKind::AuthRequired,
            Error::Io(_) | Error::Disconnected => ErrorKind::ConnectionLost,
            Error::Timeout => ErrorKind::TimedOut,
            Error::Cancelled => ErrorKind::Cancelled,
            Error::SessionExpired => ErrorKind::SessionExpired,
            Error::DfsReferralRequired { .. } => ErrorKind::DfsReferral,
            Error::Protocol { status, .. } => classify_status(*status),
        }
    }
}

/// Map an NTSTATUS to an ErrorKind.
fn classify_status(status: NtStatus) -> ErrorKind {
    match status {
        // Auth / signing
        NtStatus::LOGON_FAILURE | NtStatus::ACCOUNT_DISABLED => ErrorKind::AuthRequired,
        NtStatus::ACCESS_DENIED => {
            // Could be signing-required or genuinely access-denied.
            // Callers with NegotiatedParams context can distinguish further.
            // Default to AccessDenied; SmbClient methods can upgrade to
            // SigningRequired when signing_required is true.
            ErrorKind::AccessDenied
        }

        // Not found
        NtStatus::NO_SUCH_FILE
        | NtStatus::OBJECT_NAME_NOT_FOUND
        | NtStatus::OBJECT_PATH_NOT_FOUND
        | NtStatus::BAD_NETWORK_NAME => ErrorKind::NotFound,

        // Sharing / locking
        NtStatus::SHARING_VIOLATION | NtStatus::FILE_LOCK_CONFLICT => ErrorKind::SharingViolation,

        // Disk full
        NtStatus::DISK_FULL => ErrorKind::DiskFull,

        // Session expired
        NtStatus::NETWORK_SESSION_EXPIRED => ErrorKind::SessionExpired,

        // Connection
        NtStatus::NETWORK_NAME_DELETED | NtStatus::USER_SESSION_DELETED => {
            ErrorKind::ConnectionLost
        }

        // DFS
        NtStatus::PATH_NOT_COVERED => ErrorKind::DfsReferral,

        // Everything else
        _ => ErrorKind::Other,
    }
}

/// A `Result` type alias using the crate's [`Error`](enum@Error) type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_maps_protocol_not_found() {
        let err = Error::Protocol {
            status: NtStatus::OBJECT_NAME_NOT_FOUND,
            command: Command::Create,
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn kind_maps_protocol_access_denied() {
        let err = Error::Protocol {
            status: NtStatus::ACCESS_DENIED,
            command: Command::Create,
        };
        assert_eq!(err.kind(), ErrorKind::AccessDenied);
    }

    #[test]
    fn kind_maps_protocol_sharing_violation() {
        let err = Error::Protocol {
            status: NtStatus::SHARING_VIOLATION,
            command: Command::Create,
        };
        assert_eq!(err.kind(), ErrorKind::SharingViolation);
    }

    #[test]
    fn kind_maps_protocol_logon_failure() {
        let err = Error::Protocol {
            status: NtStatus::LOGON_FAILURE,
            command: Command::SessionSetup,
        };
        assert_eq!(err.kind(), ErrorKind::AuthRequired);
    }

    #[test]
    fn kind_maps_protocol_bad_network_name() {
        let err = Error::Protocol {
            status: NtStatus::BAD_NETWORK_NAME,
            command: Command::TreeConnect,
        };
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn kind_maps_protocol_disk_full() {
        let err = Error::Protocol {
            status: NtStatus::DISK_FULL,
            command: Command::Write,
        };
        assert_eq!(err.kind(), ErrorKind::DiskFull);
    }

    #[test]
    fn kind_maps_non_protocol_errors() {
        assert_eq!(Error::Timeout.kind(), ErrorKind::TimedOut);
        assert_eq!(Error::Disconnected.kind(), ErrorKind::ConnectionLost);
        assert_eq!(Error::Cancelled.kind(), ErrorKind::Cancelled);
        assert_eq!(Error::SessionExpired.kind(), ErrorKind::SessionExpired);
        assert_eq!(Error::invalid_data("test").kind(), ErrorKind::InvalidData);
        assert_eq!(
            Error::DfsReferralRequired {
                path: "test".into()
            }
            .kind(),
            ErrorKind::DfsReferral
        );
        assert_eq!(
            Error::Auth {
                message: "test".into()
            }
            .kind(),
            ErrorKind::AuthRequired
        );
    }

    #[test]
    fn kind_unknown_status_maps_to_other() {
        let err = Error::Protocol {
            status: NtStatus::NOT_IMPLEMENTED,
            command: Command::Ioctl,
        };
        assert_eq!(err.kind(), ErrorKind::Other);
    }
}
