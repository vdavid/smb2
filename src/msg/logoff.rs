//! SMB2 LOGOFF request and response (spec sections 2.2.7, 2.2.8).
//!
//! Logoff messages request and confirm termination of a session.
//! Both request and response contain only a StructureSize field and a
//! reserved field, for a total of 4 bytes each.

use crate::error::Result;
use crate::pack::{Pack, ReadCursor, Unpack, WriteCursor};
use crate::Error;

/// SMB2 LOGOFF request (spec section 2.2.7).
///
/// Sent by the client to request termination of a particular session.
/// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoffRequest;

impl LogoffRequest {
    /// The structure size field is always 4.
    pub const STRUCTURE_SIZE: u16 = 4;
}

impl Pack for LogoffRequest {
    fn pack(&self, cursor: &mut WriteCursor) {
        // StructureSize (2 bytes)
        cursor.write_u16_le(Self::STRUCTURE_SIZE);
        // Reserved (2 bytes)
        cursor.write_u16_le(0);
    }
}

impl Unpack for LogoffRequest {
    fn unpack(cursor: &mut ReadCursor<'_>) -> Result<Self> {
        // StructureSize (2 bytes)
        let structure_size = cursor.read_u16_le()?;
        if structure_size != Self::STRUCTURE_SIZE {
            return Err(Error::invalid_data(format!(
                "invalid LogoffRequest structure size: expected {}, got {}",
                Self::STRUCTURE_SIZE,
                structure_size
            )));
        }

        // Reserved (2 bytes)
        let _reserved = cursor.read_u16_le()?;

        Ok(LogoffRequest)
    }
}

/// SMB2 LOGOFF response (spec section 2.2.8).
///
/// Sent by the server to confirm that a LOGOFF request was processed.
/// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoffResponse;

impl LogoffResponse {
    /// The structure size field is always 4.
    pub const STRUCTURE_SIZE: u16 = 4;
}

impl Pack for LogoffResponse {
    fn pack(&self, cursor: &mut WriteCursor) {
        // StructureSize (2 bytes)
        cursor.write_u16_le(Self::STRUCTURE_SIZE);
        // Reserved (2 bytes)
        cursor.write_u16_le(0);
    }
}

impl Unpack for LogoffResponse {
    fn unpack(cursor: &mut ReadCursor<'_>) -> Result<Self> {
        // StructureSize (2 bytes)
        let structure_size = cursor.read_u16_le()?;
        if structure_size != Self::STRUCTURE_SIZE {
            return Err(Error::invalid_data(format!(
                "invalid LogoffResponse structure size: expected {}, got {}",
                Self::STRUCTURE_SIZE,
                structure_size
            )));
        }

        // Reserved (2 bytes)
        let _reserved = cursor.read_u16_le()?;

        Ok(LogoffResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LogoffRequest tests ────────────────────────────────────────

    #[test]
    fn logoff_request_pack_produces_4_bytes() {
        let req = LogoffRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn logoff_request_known_bytes() {
        let req = LogoffRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn logoff_request_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let req = LogoffRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req, LogoffRequest);
        assert!(cursor.is_empty());
    }

    #[test]
    fn logoff_request_roundtrip() {
        let original = LogoffRequest;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = LogoffRequest::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn logoff_request_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = LogoffRequest::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn logoff_request_too_short() {
        let bytes = [0x04, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = LogoffRequest::unpack(&mut cursor);
        assert!(result.is_err());
    }

    // ── LogoffResponse tests ───────────────────────────────────────

    #[test]
    fn logoff_response_pack_produces_4_bytes() {
        let resp = LogoffResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn logoff_response_known_bytes() {
        let resp = LogoffResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn logoff_response_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = LogoffResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, LogoffResponse);
        assert!(cursor.is_empty());
    }

    #[test]
    fn logoff_response_roundtrip() {
        let original = LogoffResponse;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = LogoffResponse::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn logoff_response_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = LogoffResponse::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn logoff_response_ignores_reserved_value() {
        let bytes = [0x04, 0x00, 0xFF, 0xFF];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = LogoffResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, LogoffResponse);
    }
}
