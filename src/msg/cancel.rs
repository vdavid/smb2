//! SMB2 CANCEL request (spec section 2.2.30).
//!
//! The CANCEL request is fire-and-forget: the client sends it to cancel a
//! previously sent message, and there is no corresponding response message.
//! The MessageId of the request to cancel is set in the SMB2 header.

super::trivial_message! {
    /// SMB2 CANCEL request (spec section 2.2.30).
    ///
    /// Sent by the client to cancel a previously sent message on the same
    /// transport connection. There is no response for this command.
    /// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
    pub struct CancelRequest;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{Pack, ReadCursor, Unpack, WriteCursor};

    #[test]
    fn cancel_request_pack_produces_4_bytes() {
        let req = CancelRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn cancel_request_known_bytes() {
        let req = CancelRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn cancel_request_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let req = CancelRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req, CancelRequest);
        assert!(cursor.is_empty());
    }

    #[test]
    fn cancel_request_roundtrip() {
        let original = CancelRequest;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = CancelRequest::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn cancel_request_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = CancelRequest::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn cancel_request_too_short() {
        let bytes = [0x04, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = CancelRequest::unpack(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn cancel_request_ignores_reserved_value() {
        let bytes = [0x04, 0x00, 0xAB, 0xCD];
        let mut cursor = ReadCursor::new(&bytes);
        let req = CancelRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req, CancelRequest);
    }
}
