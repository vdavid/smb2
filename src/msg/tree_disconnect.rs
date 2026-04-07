//! SMB2 TREE_DISCONNECT request and response (spec sections 2.2.11, 2.2.12).
//!
//! Tree disconnect messages request and confirm disconnection from a share.
//! Both request and response contain only a StructureSize field and a
//! reserved field, for a total of 4 bytes each.

use crate::error::Result;
use crate::pack::{Pack, ReadCursor, Unpack, WriteCursor};
use crate::Error;

/// SMB2 TREE_DISCONNECT request (spec section 2.2.11).
///
/// Sent by the client to request that the tree connect specified in the
/// TreeId within the SMB2 header be disconnected.
/// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectRequest;

impl TreeDisconnectRequest {
    /// The structure size field is always 4.
    pub const STRUCTURE_SIZE: u16 = 4;
}

impl Pack for TreeDisconnectRequest {
    fn pack(&self, cursor: &mut WriteCursor) {
        // StructureSize (2 bytes)
        cursor.write_u16_le(Self::STRUCTURE_SIZE);
        // Reserved (2 bytes)
        cursor.write_u16_le(0);
    }
}

impl Unpack for TreeDisconnectRequest {
    fn unpack(cursor: &mut ReadCursor<'_>) -> Result<Self> {
        // StructureSize (2 bytes)
        let structure_size = cursor.read_u16_le()?;
        if structure_size != Self::STRUCTURE_SIZE {
            return Err(Error::invalid_data(format!(
                "invalid TreeDisconnectRequest structure size: expected {}, got {}",
                Self::STRUCTURE_SIZE,
                structure_size
            )));
        }

        // Reserved (2 bytes)
        let _reserved = cursor.read_u16_le()?;

        Ok(TreeDisconnectRequest)
    }
}

/// SMB2 TREE_DISCONNECT response (spec section 2.2.12).
///
/// Sent by the server to confirm that a TREE_DISCONNECT request was processed.
/// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeDisconnectResponse;

impl TreeDisconnectResponse {
    /// The structure size field is always 4.
    pub const STRUCTURE_SIZE: u16 = 4;
}

impl Pack for TreeDisconnectResponse {
    fn pack(&self, cursor: &mut WriteCursor) {
        // StructureSize (2 bytes)
        cursor.write_u16_le(Self::STRUCTURE_SIZE);
        // Reserved (2 bytes)
        cursor.write_u16_le(0);
    }
}

impl Unpack for TreeDisconnectResponse {
    fn unpack(cursor: &mut ReadCursor<'_>) -> Result<Self> {
        // StructureSize (2 bytes)
        let structure_size = cursor.read_u16_le()?;
        if structure_size != Self::STRUCTURE_SIZE {
            return Err(Error::invalid_data(format!(
                "invalid TreeDisconnectResponse structure size: expected {}, got {}",
                Self::STRUCTURE_SIZE,
                structure_size
            )));
        }

        // Reserved (2 bytes)
        let _reserved = cursor.read_u16_le()?;

        Ok(TreeDisconnectResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TreeDisconnectRequest tests ────────────────────────────────

    #[test]
    fn tree_disconnect_request_pack_produces_4_bytes() {
        let req = TreeDisconnectRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn tree_disconnect_request_known_bytes() {
        let req = TreeDisconnectRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tree_disconnect_request_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let req = TreeDisconnectRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req, TreeDisconnectRequest);
        assert!(cursor.is_empty());
    }

    #[test]
    fn tree_disconnect_request_roundtrip() {
        let original = TreeDisconnectRequest;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = TreeDisconnectRequest::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tree_disconnect_request_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = TreeDisconnectRequest::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn tree_disconnect_request_too_short() {
        let bytes = [0x04, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = TreeDisconnectRequest::unpack(&mut cursor);
        assert!(result.is_err());
    }

    // ── TreeDisconnectResponse tests ───────────────────────────────

    #[test]
    fn tree_disconnect_response_pack_produces_4_bytes() {
        let resp = TreeDisconnectResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn tree_disconnect_response_known_bytes() {
        let resp = TreeDisconnectResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tree_disconnect_response_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = TreeDisconnectResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, TreeDisconnectResponse);
        assert!(cursor.is_empty());
    }

    #[test]
    fn tree_disconnect_response_roundtrip() {
        let original = TreeDisconnectResponse;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = TreeDisconnectResponse::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tree_disconnect_response_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = TreeDisconnectResponse::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn tree_disconnect_response_ignores_reserved_value() {
        let bytes = [0x04, 0x00, 0xFF, 0xFF];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = TreeDisconnectResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, TreeDisconnectResponse);
    }
}
