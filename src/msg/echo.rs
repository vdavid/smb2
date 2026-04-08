//! SMB2 ECHO request and response (spec sections 2.2.28, 2.2.29).
//!
//! Echo messages are used to check whether a server is processing requests.
//! Both request and response contain only a StructureSize field and a
//! reserved field, for a total of 4 bytes each.

super::trivial_message! {
    /// SMB2 ECHO request (spec section 2.2.28).
    ///
    /// Sent by the client to determine whether a server is processing requests.
    /// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
    pub struct EchoRequest;
}

super::trivial_message! {
    /// SMB2 ECHO response (spec section 2.2.29).
    ///
    /// Sent by the server to confirm that an ECHO request was processed.
    /// Contains only StructureSize (2 bytes) and Reserved (2 bytes).
    pub struct EchoResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{Pack, ReadCursor, Unpack, WriteCursor};

    // -- EchoRequest tests --

    #[test]
    fn echo_request_pack_produces_4_bytes() {
        let req = EchoRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn echo_request_known_bytes() {
        let req = EchoRequest;
        let mut cursor = WriteCursor::new();
        req.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn echo_request_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let req = EchoRequest::unpack(&mut cursor).unwrap();
        assert_eq!(req, EchoRequest);
        assert!(cursor.is_empty());
    }

    #[test]
    fn echo_request_roundtrip() {
        let original = EchoRequest;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = EchoRequest::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn echo_request_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = EchoRequest::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn echo_request_too_short() {
        let bytes = [0x04, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = EchoRequest::unpack(&mut cursor);
        assert!(result.is_err());
    }

    // -- EchoResponse tests --

    #[test]
    fn echo_response_pack_produces_4_bytes() {
        let resp = EchoResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn echo_response_known_bytes() {
        let resp = EchoResponse;
        let mut cursor = WriteCursor::new();
        resp.pack(&mut cursor);
        let bytes = cursor.into_inner();

        // StructureSize=4 (LE), Reserved=0
        assert_eq!(bytes, [0x04, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn echo_response_unpack_known_bytes() {
        let bytes = [0x04, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = EchoResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, EchoResponse);
        assert!(cursor.is_empty());
    }

    #[test]
    fn echo_response_roundtrip() {
        let original = EchoResponse;
        let mut w = WriteCursor::new();
        original.pack(&mut w);
        let bytes = w.into_inner();

        let mut r = ReadCursor::new(&bytes);
        let decoded = EchoResponse::unpack(&mut r).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn echo_response_wrong_structure_size() {
        let bytes = [0x08, 0x00, 0x00, 0x00];
        let mut cursor = ReadCursor::new(&bytes);
        let result = EchoResponse::unpack(&mut cursor);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("structure size"), "error was: {err}");
    }

    #[test]
    fn echo_response_ignores_reserved_value() {
        // Reserved field can be anything on unpack (server sets 0, but we ignore)
        let bytes = [0x04, 0x00, 0xFF, 0xFF];
        let mut cursor = ReadCursor::new(&bytes);
        let resp = EchoResponse::unpack(&mut cursor).unwrap();
        assert_eq!(resp, EchoResponse);
    }
}
