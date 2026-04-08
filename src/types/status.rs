//! NTSTATUS codes used by SMB2/3 (from MS-ERREF).

use std::fmt;

/// NT status code returned in SMB2 response headers.
///
/// The top two bits encode severity:
/// - `00` = success
/// - `01` = informational
/// - `10` = warning
/// - `11` = error
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtStatus(pub u32);

impl NtStatus {
    // ── Success (severity 0b00) ──────────────────────────────────────

    /// The operation completed successfully.
    pub const SUCCESS: Self = Self(0x0000_0000);

    /// The operation that was requested is pending completion.
    pub const PENDING: Self = Self(0x0000_0103);

    /// Oplock break notification (informational).
    pub const NOTIFY_ENUM_DIR: Self = Self(0x0000_010C);

    // ── Informational (severity 0b00, facility-specific) ─────────────

    /// The authentication exchange is not complete — send the next
    /// SESSION_SETUP with the GSS token from this response.
    ///
    /// **Important:** The severity bits are 0b11 (error), so `is_error()`
    /// returns `true`. But this is NOT a real error — it's a "keep going"
    /// signal during NTLM/SPNEGO auth. Auth code must check
    /// `is_more_processing_required()` before checking `is_error()`.
    pub const MORE_PROCESSING_REQUIRED: Self = Self(0xC000_0016);

    // ── Warnings (severity 0b10) ─────────────────────────────────────

    /// The data was too large to fit into the specified buffer.
    /// This is a warning — the response body contains valid partial data.
    pub const BUFFER_OVERFLOW: Self = Self(0x8000_0005);

    /// No more files were found which match the file specification.
    pub const NO_MORE_FILES: Self = Self(0x8000_0006);

    // ── Errors (severity 0b11) ───────────────────────────────────────

    /// The requested operation was unsuccessful.
    pub const UNSUCCESSFUL: Self = Self(0xC000_0001);

    /// The requested operation is not implemented.
    pub const NOT_IMPLEMENTED: Self = Self(0xC000_0002);

    /// An invalid parameter was passed to a service or function.
    pub const INVALID_PARAMETER: Self = Self(0xC000_000D);

    /// A device that does not exist was specified.
    pub const NO_SUCH_DEVICE: Self = Self(0xC000_000E);

    /// The file does not exist.
    pub const NO_SUCH_FILE: Self = Self(0xC000_000F);

    /// The specified request is not a valid operation for the target device.
    pub const INVALID_DEVICE_REQUEST: Self = Self(0xC000_0010);

    /// The end-of-file marker has been reached.
    pub const END_OF_FILE: Self = Self(0xC000_0011);

    /// A process has requested access to an object but has not been
    /// granted those access rights.
    pub const ACCESS_DENIED: Self = Self(0xC000_0022);

    /// The buffer is too small to contain the entry.
    pub const BUFFER_TOO_SMALL: Self = Self(0xC000_0023);

    /// The object name is not found.
    pub const OBJECT_NAME_NOT_FOUND: Self = Self(0xC000_0034);

    /// The object name already exists.
    pub const OBJECT_NAME_COLLISION: Self = Self(0xC000_0035);

    /// The path does not exist.
    pub const OBJECT_PATH_NOT_FOUND: Self = Self(0xC000_003A);

    /// A file cannot be opened because the share access flags
    /// are incompatible.
    pub const SHARING_VIOLATION: Self = Self(0xC000_0043);

    /// A requested read/write cannot be granted due to a conflicting
    /// file lock.
    pub const FILE_LOCK_CONFLICT: Self = Self(0xC000_0054);

    /// A non-close operation has been requested of a file object that
    /// has a delete pending.
    pub const DELETE_PENDING: Self = Self(0xC000_0056);

    /// The attempted logon is invalid.
    pub const LOGON_FAILURE: Self = Self(0xC000_006D);

    /// The referenced account is currently disabled.
    pub const ACCOUNT_DISABLED: Self = Self(0xC000_0072);

    /// Insufficient system resources exist to complete the API.
    pub const INSUFFICIENT_RESOURCES: Self = Self(0xC000_009A);

    /// The file that was specified as a target is a directory.
    pub const FILE_IS_A_DIRECTORY: Self = Self(0xC000_00BA);

    /// The network path cannot be located.
    pub const BAD_NETWORK_PATH: Self = Self(0xC000_00BE);

    /// The network name was deleted.
    pub const NETWORK_NAME_DELETED: Self = Self(0xC000_00C9);

    /// The specified share name cannot be found on the remote server.
    pub const BAD_NETWORK_NAME: Self = Self(0xC000_00CC);

    /// No more connections can be made to this remote computer at this time.
    pub const REQUEST_NOT_ACCEPTED: Self = Self(0xC000_00D0);

    /// A requested opened file is not a directory.
    pub const NOT_A_DIRECTORY: Self = Self(0xC000_0103);

    /// The I/O request was canceled.
    pub const CANCELLED: Self = Self(0xC000_0120);

    /// An I/O request other than close was attempted using a file object
    /// that had already been closed.
    pub const FILE_CLOSED: Self = Self(0xC000_0128);

    /// The remote user session has been deleted.
    pub const USER_SESSION_DELETED: Self = Self(0xC000_0203);

    /// Insufficient server resources exist to complete the request.
    pub const INSUFF_SERVER_RESOURCES: Self = Self(0xC000_0205);

    /// The object was not found.
    pub const NOT_FOUND: Self = Self(0xC000_0225);

    /// The contacted server does not support the indicated part
    /// of the DFS namespace.
    pub const PATH_NOT_COVERED: Self = Self(0xC000_0257);

    /// The client session has expired; the client must re-authenticate.
    pub const NETWORK_SESSION_EXPIRED: Self = Self(0xC000_035C);

    // ── Helper methods ───────────────────────────────────────────────

    /// Returns the severity bits (top 2 bits): 0 = success, 1 = info,
    /// 2 = warning, 3 = error.
    #[inline]
    pub fn severity(&self) -> u8 {
        (self.0 >> 30) as u8
    }

    /// Returns `true` if the status indicates success (severity 0b00).
    #[inline]
    pub fn is_success(&self) -> bool {
        self.severity() == 0
    }

    /// Returns `true` if the status is a warning (severity 0b10).
    #[inline]
    pub fn is_warning(&self) -> bool {
        self.severity() == 2
    }

    /// Returns `true` if the status is an error (severity 0b11).
    #[inline]
    pub fn is_error(&self) -> bool {
        self.severity() == 3
    }

    /// Returns `true` if this is `STATUS_PENDING`.
    #[inline]
    pub fn is_pending(&self) -> bool {
        *self == Self::PENDING
    }

    /// Returns `true` if the server wants another SESSION_SETUP round-trip.
    ///
    /// Check this BEFORE `is_error()` during authentication — it has
    /// error severity bits but is not a real error.
    #[inline]
    pub fn is_more_processing_required(&self) -> bool {
        *self == Self::MORE_PROCESSING_REQUIRED
    }

    /// Returns a human-readable name for known status codes,
    /// or `None` for unknown codes.
    fn name(&self) -> Option<&'static str> {
        match self.0 {
            0x0000_0000 => Some("STATUS_SUCCESS"),
            0x0000_0103 => Some("STATUS_PENDING"),
            0x0000_010C => Some("STATUS_NOTIFY_ENUM_DIR"),
            0xC000_0016 => Some("STATUS_MORE_PROCESSING_REQUIRED"),
            0x8000_0005 => Some("STATUS_BUFFER_OVERFLOW"),
            0x8000_0006 => Some("STATUS_NO_MORE_FILES"),
            0xC000_0001 => Some("STATUS_UNSUCCESSFUL"),
            0xC000_0002 => Some("STATUS_NOT_IMPLEMENTED"),
            0xC000_000D => Some("STATUS_INVALID_PARAMETER"),
            0xC000_000E => Some("STATUS_NO_SUCH_DEVICE"),
            0xC000_000F => Some("STATUS_NO_SUCH_FILE"),
            0xC000_0010 => Some("STATUS_INVALID_DEVICE_REQUEST"),
            0xC000_0011 => Some("STATUS_END_OF_FILE"),
            0xC000_0022 => Some("STATUS_ACCESS_DENIED"),
            0xC000_0023 => Some("STATUS_BUFFER_TOO_SMALL"),
            0xC000_0034 => Some("STATUS_OBJECT_NAME_NOT_FOUND"),
            0xC000_0035 => Some("STATUS_OBJECT_NAME_COLLISION"),
            0xC000_003A => Some("STATUS_OBJECT_PATH_NOT_FOUND"),
            0xC000_0043 => Some("STATUS_SHARING_VIOLATION"),
            0xC000_0054 => Some("STATUS_FILE_LOCK_CONFLICT"),
            0xC000_0056 => Some("STATUS_DELETE_PENDING"),
            0xC000_006D => Some("STATUS_LOGON_FAILURE"),
            0xC000_0072 => Some("STATUS_ACCOUNT_DISABLED"),
            0xC000_009A => Some("STATUS_INSUFFICIENT_RESOURCES"),
            0xC000_00BA => Some("STATUS_FILE_IS_A_DIRECTORY"),
            0xC000_00BE => Some("STATUS_BAD_NETWORK_PATH"),
            0xC000_00C9 => Some("STATUS_NETWORK_NAME_DELETED"),
            0xC000_00CC => Some("STATUS_BAD_NETWORK_NAME"),
            0xC000_00D0 => Some("STATUS_REQUEST_NOT_ACCEPTED"),
            0xC000_0103 => Some("STATUS_NOT_A_DIRECTORY"),
            0xC000_0120 => Some("STATUS_CANCELLED"),
            0xC000_0128 => Some("STATUS_FILE_CLOSED"),
            0xC000_0203 => Some("STATUS_USER_SESSION_DELETED"),
            0xC000_0205 => Some("STATUS_INSUFF_SERVER_RESOURCES"),
            0xC000_0225 => Some("STATUS_NOT_FOUND"),
            0xC000_0257 => Some("STATUS_PATH_NOT_COVERED"),
            0xC000_035C => Some("STATUS_NETWORK_SESSION_EXPIRED"),
            _ => None,
        }
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "NtStatus({name})"),
            None => write!(f, "NtStatus(0x{:08X})", self.0),
        }
    }
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "0x{:08X}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_success() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(!NtStatus::SUCCESS.is_error());
        assert!(!NtStatus::SUCCESS.is_warning());
        assert_eq!(NtStatus::SUCCESS.severity(), 0);
    }

    #[test]
    fn access_denied_is_error() {
        assert!(NtStatus::ACCESS_DENIED.is_error());
        assert!(!NtStatus::ACCESS_DENIED.is_success());
        assert!(!NtStatus::ACCESS_DENIED.is_warning());
        assert_eq!(NtStatus::ACCESS_DENIED.severity(), 3);
    }

    #[test]
    fn buffer_overflow_is_warning() {
        assert!(NtStatus::BUFFER_OVERFLOW.is_warning());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_success());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_error());
        assert_eq!(NtStatus::BUFFER_OVERFLOW.severity(), 2);
    }

    #[test]
    fn pending_is_pending() {
        assert!(NtStatus::PENDING.is_pending());
        assert!(NtStatus::PENDING.is_success()); // severity 0b00
        assert!(!NtStatus::SUCCESS.is_pending());
    }

    #[test]
    fn more_processing_required_is_error_severity() {
        // 0xC0000016 has severity 0b11 (error), even though semantically
        // it means "keep going" during authentication handshakes.
        assert!(NtStatus::MORE_PROCESSING_REQUIRED.is_error());
        assert_eq!(NtStatus::MORE_PROCESSING_REQUIRED.severity(), 3);
    }

    #[test]
    fn display_known_code() {
        assert_eq!(NtStatus::ACCESS_DENIED.to_string(), "STATUS_ACCESS_DENIED");
    }

    #[test]
    fn display_unknown_code() {
        let unknown = NtStatus(0xDEAD_BEEF);
        assert_eq!(unknown.to_string(), "0xDEADBEEF");
    }

    #[test]
    fn debug_known_code() {
        let s = format!("{:?}", NtStatus::SUCCESS);
        assert_eq!(s, "NtStatus(STATUS_SUCCESS)");
    }

    #[test]
    fn debug_unknown_code() {
        let s = format!("{:?}", NtStatus(0x1234_5678));
        assert_eq!(s, "NtStatus(0x12345678)");
    }

    #[test]
    fn no_more_files_is_warning() {
        assert!(NtStatus::NO_MORE_FILES.is_warning());
    }

    #[test]
    fn default_is_success() {
        assert_eq!(NtStatus::default(), NtStatus::SUCCESS);
    }

    #[test]
    fn all_error_codes_have_error_severity() {
        let errors = [
            NtStatus::UNSUCCESSFUL,
            NtStatus::NOT_IMPLEMENTED,
            NtStatus::INVALID_PARAMETER,
            NtStatus::NO_SUCH_DEVICE,
            NtStatus::NO_SUCH_FILE,
            NtStatus::END_OF_FILE,
            NtStatus::ACCESS_DENIED,
            NtStatus::BUFFER_TOO_SMALL,
            NtStatus::OBJECT_NAME_NOT_FOUND,
            NtStatus::OBJECT_NAME_COLLISION,
            NtStatus::OBJECT_PATH_NOT_FOUND,
            NtStatus::SHARING_VIOLATION,
            NtStatus::FILE_LOCK_CONFLICT,
            NtStatus::DELETE_PENDING,
            NtStatus::LOGON_FAILURE,
            NtStatus::ACCOUNT_DISABLED,
            NtStatus::INSUFFICIENT_RESOURCES,
            NtStatus::FILE_IS_A_DIRECTORY,
            NtStatus::BAD_NETWORK_PATH,
            NtStatus::NETWORK_NAME_DELETED,
            NtStatus::BAD_NETWORK_NAME,
            NtStatus::REQUEST_NOT_ACCEPTED,
            NtStatus::NOT_A_DIRECTORY,
            NtStatus::CANCELLED,
            NtStatus::FILE_CLOSED,
            NtStatus::USER_SESSION_DELETED,
            NtStatus::INSUFF_SERVER_RESOURCES,
            NtStatus::NOT_FOUND,
            NtStatus::PATH_NOT_COVERED,
            NtStatus::NETWORK_SESSION_EXPIRED,
            NtStatus::MORE_PROCESSING_REQUIRED,
        ];
        for status in &errors {
            assert!(
                status.is_error(),
                "{status} should be error but severity is {}",
                status.severity()
            );
        }
    }
}
