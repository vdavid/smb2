//! Wire format tests against a real SMB2 server.
//!
//! These tests connect to a real NAS on the local network, send packed SMB2
//! messages, and verify we can parse the real server responses. They are
//! marked `#[ignore]` so they only run when explicitly requested:
//!
//! ```sh
//! cargo test --test wire_format_captures -- --ignored
//! ```
//!
//! Required: a NAS at 192.168.1.111:445 with an SMB share named "naspi".

use smb2::msg::header::{Header, PROTOCOL_ID};
use smb2::msg::negotiate::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, CIPHER_AES_128_CCM, CIPHER_AES_128_GCM,
    CIPHER_AES_256_CCM, CIPHER_AES_256_GCM, HASH_ALGORITHM_SHA512, SIGNING_AES_CMAC,
    SIGNING_AES_GMAC, SIGNING_HMAC_SHA256,
};
use smb2::pack::{Guid, Pack, ReadCursor, Unpack, WriteCursor};
use smb2::types::flags::{Capabilities, SecurityMode};
use smb2::types::status::NtStatus;
use smb2::types::{Command, Dialect};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NAS_ADDR: &str = "192.168.1.111:445";

/// Build the NetBIOS session service frame (4 bytes): 0x00 + 3-byte BE length.
fn netbios_frame(smb2_msg: &[u8]) -> Vec<u8> {
    let len = smb2_msg.len() as u32;
    let mut frame = Vec::with_capacity(4 + smb2_msg.len());
    frame.push(0x00);
    frame.push((len >> 16) as u8);
    frame.push((len >> 8) as u8);
    frame.push(len as u8);
    frame.extend_from_slice(smb2_msg);
    frame
}

/// Read a single SMB2 message from the stream (NetBIOS framing).
/// Returns the raw SMB2 message bytes (without the 4-byte NetBIOS header).
async fn read_smb2_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut frame_header = [0u8; 4];
    stream
        .read_exact(&mut frame_header)
        .await
        .expect("failed to read NetBIOS frame header");

    assert_eq!(
        frame_header[0], 0x00,
        "expected NetBIOS session message type 0x00, got 0x{:02X}",
        frame_header[0]
    );

    let msg_len = ((frame_header[1] as usize) << 16)
        | ((frame_header[2] as usize) << 8)
        | (frame_header[3] as usize);

    assert!(
        msg_len > 0 && msg_len < 16 * 1024 * 1024,
        "suspicious message length: {}",
        msg_len
    );

    let mut buf = vec![0u8; msg_len];
    stream
        .read_exact(&mut buf)
        .await
        .expect("failed to read SMB2 message body");
    buf
}

/// Build a NegotiateRequest with all dialects and SMB 3.1.1 negotiate contexts.
fn build_negotiate_request() -> (Header, NegotiateRequest) {
    let header = Header::new_request(Command::Negotiate);

    // Generate a random-ish client GUID (deterministic for tests).
    let client_guid = Guid {
        data1: 0xDEAD_BEEF,
        data2: 0xCAFE,
        data3: 0xF00D,
        data4: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };

    let request = NegotiateRequest {
        security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
        capabilities: Capabilities::new(
            Capabilities::DFS | Capabilities::LEASING | Capabilities::LARGE_MTU,
        ),
        client_guid,
        dialects: vec![
            Dialect::Smb2_0_2,
            Dialect::Smb2_1,
            Dialect::Smb3_0,
            Dialect::Smb3_0_2,
            Dialect::Smb3_1_1,
        ],
        negotiate_contexts: vec![
            NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                salt: vec![
                    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0,
                    0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
                ],
            },
            NegotiateContext::Encryption {
                ciphers: vec![
                    CIPHER_AES_128_GCM,
                    CIPHER_AES_128_CCM,
                    CIPHER_AES_256_GCM,
                    CIPHER_AES_256_CCM,
                ],
            },
            NegotiateContext::Signing {
                algorithms: vec![SIGNING_AES_CMAC, SIGNING_HMAC_SHA256, SIGNING_AES_GMAC],
            },
        ],
    };

    (header, request)
}

/// Pack a header + body into a complete SMB2 message (no NetBIOS framing).
fn pack_message(header: &Header, body: &dyn Pack) -> Vec<u8> {
    let mut cursor = WriteCursor::new();
    header.pack(&mut cursor);
    body.pack(&mut cursor);
    cursor.into_inner()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires NAS at 192.168.1.111
async fn negotiate_request_is_accepted_by_real_server() {
    // Connect to the server.
    let mut stream = TcpStream::connect(NAS_ADDR)
        .await
        .expect("failed to connect to NAS -- is it reachable?");

    // Build and pack the negotiate request.
    let (header, request) = build_negotiate_request();
    let msg = pack_message(&header, &request);

    // Verify our packed message starts with the SMB2 protocol ID.
    assert_eq!(
        &msg[0..4],
        &PROTOCOL_ID,
        "packed message should start with SMB2 magic"
    );

    // Send with NetBIOS framing.
    let frame = netbios_frame(&msg);
    stream
        .write_all(&frame)
        .await
        .expect("failed to send negotiate request");

    // Read the response.
    let resp_bytes = read_smb2_message(&mut stream).await;

    // Print raw bytes for future use as offline test vectors.
    println!("--- Negotiate response ({} bytes) ---", resp_bytes.len());
    println!("Raw hex: {:02x?}", &resp_bytes);

    // Parse the response header.
    let mut cursor = ReadCursor::new(&resp_bytes);
    let resp_header = Header::unpack(&mut cursor).expect("failed to unpack response header");

    // Verify header fields.
    assert!(
        resp_header.is_response(),
        "server response should have the response flag set"
    );
    assert_eq!(
        resp_header.command,
        Command::Negotiate,
        "response should be for Negotiate command"
    );
    assert_eq!(
        resp_header.status,
        NtStatus::SUCCESS,
        "negotiate should succeed (got status 0x{:08X})",
        resp_header.status.0
    );
    assert_eq!(
        resp_header.message_id.0, 0,
        "response message ID should match request (0)"
    );

    // Parse the response body.
    let resp_body =
        NegotiateResponse::unpack(&mut cursor).expect("failed to unpack NegotiateResponse body");

    // Verify the response makes sense.
    println!("Negotiated dialect: {}", resp_body.dialect_revision);
    println!("Server GUID: {}", resp_body.server_guid);
    println!("Max read size: {}", resp_body.max_read_size);
    println!("Max write size: {}", resp_body.max_write_size);
    println!("Max transact size: {}", resp_body.max_transact_size);
    println!("Security mode: {:?}", resp_body.security_mode);
    println!("Capabilities: {:?}", resp_body.capabilities);
    println!(
        "Security buffer length: {} bytes",
        resp_body.security_buffer.len()
    );
    println!(
        "Negotiate contexts: {} items",
        resp_body.negotiate_contexts.len()
    );

    // The server should pick one of the dialects we offered.
    assert!(
        Dialect::ALL.contains(&resp_body.dialect_revision),
        "server should pick a valid dialect, got {:?}",
        resp_body.dialect_revision
    );

    // Max sizes should be at least 64 KB (every real server supports this).
    assert!(
        resp_body.max_read_size >= 65536,
        "max_read_size should be >= 64KB, got {}",
        resp_body.max_read_size
    );
    assert!(
        resp_body.max_write_size >= 65536,
        "max_write_size should be >= 64KB, got {}",
        resp_body.max_write_size
    );
    assert!(
        resp_body.max_transact_size >= 65536,
        "max_transact_size should be >= 64KB, got {}",
        resp_body.max_transact_size
    );

    // Signing should be enabled.
    assert!(
        resp_body.security_mode.signing_enabled(),
        "server should have signing enabled"
    );

    // Server should provide a security buffer (GSS/SPNEGO token).
    assert!(
        !resp_body.security_buffer.is_empty(),
        "server should send a non-empty security buffer (SPNEGO token)"
    );

    // System time should be non-zero (it's a FILETIME of the current time).
    assert!(resp_body.system_time > 0, "system_time should be non-zero");

    // If SMB 3.1.1 was negotiated, verify negotiate contexts.
    if resp_body.dialect_revision == Dialect::Smb3_1_1 {
        assert!(
            !resp_body.negotiate_contexts.is_empty(),
            "SMB 3.1.1 response should have negotiate contexts"
        );

        // Should have at least a PreauthIntegrity context.
        let has_preauth = resp_body
            .negotiate_contexts
            .iter()
            .any(|ctx| matches!(ctx, NegotiateContext::PreauthIntegrity { .. }));
        assert!(
            has_preauth,
            "SMB 3.1.1 response should include PreauthIntegrity context"
        );

        for ctx in &resp_body.negotiate_contexts {
            match ctx {
                NegotiateContext::PreauthIntegrity {
                    hash_algorithms,
                    salt,
                } => {
                    println!(
                        "  PreauthIntegrity: algorithms={:?}, salt_len={}",
                        hash_algorithms,
                        salt.len()
                    );
                    assert!(
                        hash_algorithms.contains(&HASH_ALGORITHM_SHA512),
                        "server should select SHA-512 for preauth integrity"
                    );
                    assert!(!salt.is_empty(), "server preauth salt should be non-empty");
                }
                NegotiateContext::Encryption { ciphers } => {
                    println!("  Encryption: ciphers={:?}", ciphers);
                    assert!(
                        !ciphers.is_empty(),
                        "encryption context should list at least one cipher"
                    );
                }
                NegotiateContext::Signing { algorithms } => {
                    println!("  Signing: algorithms={:?}", algorithms);
                    assert!(
                        !algorithms.is_empty(),
                        "signing context should list at least one algorithm"
                    );
                }
                NegotiateContext::Compression { algorithms, flags } => {
                    println!(
                        "  Compression: flags=0x{:08X}, algorithms={:?}",
                        flags, algorithms
                    );
                }
                NegotiateContext::Unknown { context_type, data } => {
                    println!(
                        "  Unknown context: type=0x{:04X}, data_len={}",
                        context_type,
                        data.len()
                    );
                }
            }
        }
    }
}

#[tokio::test]
#[ignore] // Requires NAS at 192.168.1.111
async fn negotiate_request_roundtrips_through_pack_unpack() {
    // Verify that our packed NegotiateRequest can be unpacked back to the
    // same logical content (testing our own pack/unpack, not the server).
    let (header, request) = build_negotiate_request();
    let msg = pack_message(&header, &request);

    // Unpack the header.
    let mut cursor = ReadCursor::new(&msg);
    let rt_header = Header::unpack(&mut cursor).expect("failed to unpack our own header");
    assert_eq!(rt_header.command, Command::Negotiate);
    assert!(!rt_header.is_response());

    // Unpack the body.
    let rt_request =
        NegotiateRequest::unpack(&mut cursor).expect("failed to unpack our own NegotiateRequest");

    assert_eq!(rt_request.dialects, request.dialects);
    assert_eq!(
        rt_request.security_mode.bits(),
        request.security_mode.bits()
    );
    assert_eq!(rt_request.capabilities.bits(), request.capabilities.bits());
    assert_eq!(rt_request.client_guid, request.client_guid);
    assert_eq!(
        rt_request.negotiate_contexts.len(),
        request.negotiate_contexts.len()
    );
}

#[tokio::test]
#[ignore] // Requires NAS at 192.168.1.111
async fn negotiate_response_repacks_to_same_bytes() {
    // Connect, negotiate, then verify that unpacking and repacking the
    // response produces identical bytes (modulo padding). This is a strong
    // test that our pack/unpack are faithful to the wire format.
    let mut stream = TcpStream::connect(NAS_ADDR)
        .await
        .expect("failed to connect to NAS");

    let (header, request) = build_negotiate_request();
    let msg = pack_message(&header, &request);
    let frame = netbios_frame(&msg);

    stream.write_all(&frame).await.unwrap();
    let resp_bytes = read_smb2_message(&mut stream).await;

    // Unpack everything.
    let mut cursor = ReadCursor::new(&resp_bytes);
    let resp_header = Header::unpack(&mut cursor).unwrap();
    let resp_body = NegotiateResponse::unpack(&mut cursor).unwrap();

    // Repack.
    let repacked = pack_message(&resp_header, &resp_body);

    // The repacked bytes should match the original up to the length of
    // our repacked output (some servers may send trailing bytes or padding).
    let compare_len = repacked.len().min(resp_bytes.len());
    if repacked[..compare_len] != resp_bytes[..compare_len] {
        // Find first difference for debugging.
        for (i, (a, b)) in repacked.iter().zip(resp_bytes.iter()).enumerate() {
            if a != b {
                panic!(
                    "repack mismatch at byte {}: packed 0x{:02X} vs original 0x{:02X}\n\
                     packed:   {:02x?}\n\
                     original: {:02x?}",
                    i,
                    a,
                    b,
                    &repacked[i.saturating_sub(4)..repacked.len().min(i + 8)],
                    &resp_bytes[i.saturating_sub(4)..resp_bytes.len().min(i + 8)],
                );
            }
        }
    }

    println!("Repack test passed: {} bytes match perfectly", compare_len);
}

#[tokio::test]
#[ignore] // Requires NAS at 192.168.1.111
async fn negotiate_only_smb2_dialects() {
    // Test with only SMB 2.x dialects (no 3.1.1 negotiate contexts).
    let mut stream = TcpStream::connect(NAS_ADDR)
        .await
        .expect("failed to connect to NAS");

    let header = Header::new_request(Command::Negotiate);
    let request = NegotiateRequest {
        security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
        capabilities: Capabilities::default(),
        client_guid: Guid {
            data1: 0x1111_2222,
            data2: 0x3333,
            data3: 0x4444,
            data4: [0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC],
        },
        dialects: vec![Dialect::Smb2_0_2, Dialect::Smb2_1],
        negotiate_contexts: vec![],
    };

    let msg = pack_message(&header, &request);
    let frame = netbios_frame(&msg);

    stream.write_all(&frame).await.unwrap();
    let resp_bytes = read_smb2_message(&mut stream).await;

    let mut cursor = ReadCursor::new(&resp_bytes);
    let resp_header = Header::unpack(&mut cursor).unwrap();

    assert!(resp_header.is_response());
    assert_eq!(resp_header.command, Command::Negotiate);

    if resp_header.status == NtStatus::SUCCESS {
        let resp_body = NegotiateResponse::unpack(&mut cursor).unwrap();

        // Should pick SMB 2.x.
        assert!(
            resp_body.dialect_revision == Dialect::Smb2_0_2
                || resp_body.dialect_revision == Dialect::Smb2_1,
            "server should pick SMB 2.x dialect when only 2.x offered, got {:?}",
            resp_body.dialect_revision
        );

        // No negotiate contexts for pre-3.1.1.
        assert!(
            resp_body.negotiate_contexts.is_empty(),
            "no negotiate contexts expected for SMB 2.x"
        );

        println!(
            "SMB 2.x-only negotiate succeeded with dialect: {}",
            resp_body.dialect_revision
        );
    } else {
        println!(
            "Server rejected SMB 2.x-only negotiate with status 0x{:08X} (this is acceptable \
             if the server requires SMB 3.x)",
            resp_header.status.0
        );
    }
}

#[tokio::test]
#[ignore] // Requires NAS at 192.168.1.111
async fn packed_header_bytes_match_protocol_spec() {
    // Verify that the first 64 bytes we send have the correct structure
    // according to MS-SMB2 section 2.2.1.
    let (header, request) = build_negotiate_request();
    let msg = pack_message(&header, &request);

    // Bytes 0-3: ProtocolId = 0xFE 'S' 'M' 'B'
    assert_eq!(&msg[0..4], &[0xFE, 0x53, 0x4D, 0x42]);

    // Bytes 4-5: StructureSize = 64 (LE)
    assert_eq!(&msg[4..6], &64u16.to_le_bytes());

    // Bytes 6-7: CreditCharge = 0 (default)
    assert_eq!(&msg[6..8], &0u16.to_le_bytes());

    // Bytes 8-11: Status = 0 (SUCCESS)
    assert_eq!(&msg[8..12], &0u32.to_le_bytes());

    // Bytes 12-13: Command = Negotiate (0x0000)
    assert_eq!(&msg[12..14], &0u16.to_le_bytes());

    // Bytes 14-15: CreditRequest = 1
    assert_eq!(&msg[14..16], &1u16.to_le_bytes());

    // Bytes 16-19: Flags = 0 (request, sync)
    assert_eq!(&msg[16..20], &0u32.to_le_bytes());

    // Bytes 20-23: NextCommand = 0 (no chaining)
    assert_eq!(&msg[20..24], &0u32.to_le_bytes());

    // Bytes 24-31: MessageId = 0
    assert_eq!(&msg[24..32], &0u64.to_le_bytes());

    // Bytes 32-35: Reserved = 0 (sync header)
    assert_eq!(&msg[32..36], &0u32.to_le_bytes());

    // Bytes 36-39: TreeId = 0
    assert_eq!(&msg[36..40], &0u32.to_le_bytes());

    // Bytes 40-47: SessionId = 0
    assert_eq!(&msg[40..48], &0u64.to_le_bytes());

    // Bytes 48-63: Signature = all zeros
    assert_eq!(&msg[48..64], &[0u8; 16]);

    // Total header size is 64.
    assert!(
        msg.len() >= 64,
        "message should be at least 64 bytes (header)"
    );

    // Byte 64-65: NegotiateRequest StructureSize = 36 (LE)
    assert_eq!(&msg[64..66], &36u16.to_le_bytes());

    println!(
        "Header byte layout verified: {} total message bytes",
        msg.len()
    );
}
