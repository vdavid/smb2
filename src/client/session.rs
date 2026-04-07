//! Authenticated SMB2 session.
//!
//! The [`Session`] type manages the multi-round-trip SESSION_SETUP exchange
//! (NTLM authentication), key derivation, and signing activation.

use crate::auth::ntlm::{NtlmAuthenticator, NtlmCredentials};
use crate::client::connection::Connection;
use crate::crypto::kdf::derive_session_keys;
use crate::crypto::signing::{algorithm_for_dialect, SigningAlgorithm};
use crate::error::Result;
use crate::msg::session_setup::{SessionSetupRequest, SessionSetupResponse};
use crate::pack::{ReadCursor, Unpack};
use crate::types::flags::{Capabilities, SecurityMode};
use crate::types::status::NtStatus;
use crate::types::{Command, Dialect, SessionId};
use crate::Error;

use crate::msg::session_setup::SessionSetupRequestFlags;

/// An authenticated SMB2 session with derived keys.
#[derive(Debug)]
pub struct Session {
    /// The session ID assigned by the server.
    pub session_id: SessionId,
    /// Key used to sign outgoing messages.
    pub signing_key: Vec<u8>,
    /// Key used to encrypt outgoing messages (SMB 3.x).
    pub encryption_key: Option<Vec<u8>>,
    /// Key used to decrypt incoming messages (SMB 3.x).
    pub decryption_key: Option<Vec<u8>>,
    /// The signing algorithm to use.
    pub signing_algorithm: SigningAlgorithm,
    /// Whether outgoing messages should be signed.
    pub should_sign: bool,
    /// Whether outgoing messages should be encrypted.
    pub should_encrypt: bool,
}

impl Session {
    /// Perform the multi-round-trip SESSION_SETUP exchange.
    ///
    /// Steps:
    /// 1. Send NTLM NEGOTIATE_MESSAGE in SESSION_SETUP.
    /// 2. Receive STATUS_MORE_PROCESSING_REQUIRED with CHALLENGE_MESSAGE.
    /// 3. Update preauth hash with request+response.
    /// 4. Send NTLM AUTHENTICATE_MESSAGE in SESSION_SETUP.
    /// 5. Receive STATUS_SUCCESS with session flags.
    /// 6. Update preauth hash with request+response.
    /// 7. Derive signing/encryption keys.
    /// 8. Activate signing on the connection.
    pub async fn setup(
        conn: &mut Connection,
        username: &str,
        password: &str,
        domain: &str,
    ) -> Result<Session> {
        let params = conn
            .params()
            .ok_or_else(|| Error::invalid_data("negotiate must complete before session setup"))?
            .clone();

        let mut auth = NtlmAuthenticator::new(NtlmCredentials {
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
        });

        // Clone the preauth hasher for this session (spec: per-session hash).
        let mut session_hasher = conn.preauth_hasher().clone();

        // ── Round 1: NEGOTIATE_MESSAGE ──

        let type1_bytes = auth.negotiate();

        let req1 = SessionSetupRequest {
            flags: SessionSetupRequestFlags(0),
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            capabilities: Capabilities::default(),
            channel: 0,
            previous_session_id: 0,
            security_buffer: type1_bytes,
        };

        let (_, req1_raw) = conn
            .send_request(Command::SessionSetup, &req1, None)
            .await?;

        // Update session preauth hash with request.
        session_hasher.update(&req1_raw);

        let (resp1_header, resp1_body, resp1_raw) = conn.receive_response().await?;

        // Update session preauth hash with response.
        session_hasher.update(&resp1_raw);

        if resp1_header.command != Command::SessionSetup {
            return Err(Error::invalid_data(format!(
                "expected SessionSetup response, got {:?}",
                resp1_header.command
            )));
        }

        if !resp1_header.status.is_more_processing_required() {
            if resp1_header.status.is_error() {
                return Err(Error::Protocol {
                    status: resp1_header.status,
                    command: Command::SessionSetup,
                });
            }
            return Err(Error::invalid_data(
                "expected STATUS_MORE_PROCESSING_REQUIRED, got success on first round",
            ));
        }

        // The server assigned a session ID — use it for subsequent requests.
        conn.set_session_id(resp1_header.session_id);

        // Parse the challenge response.
        let mut cursor1 = ReadCursor::new(&resp1_body);
        let setup_resp1 = SessionSetupResponse::unpack(&mut cursor1)?;

        // ── Round 2: AUTHENTICATE_MESSAGE ──

        let type3_bytes = auth.authenticate(&setup_resp1.security_buffer)?;

        let req2 = SessionSetupRequest {
            flags: SessionSetupRequestFlags(0),
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            capabilities: Capabilities::default(),
            channel: 0,
            previous_session_id: 0,
            security_buffer: type3_bytes,
        };

        let (_, req2_raw) = conn
            .send_request(Command::SessionSetup, &req2, None)
            .await?;

        // Update session preauth hash with request.
        session_hasher.update(&req2_raw);

        let (resp2_header, resp2_body, resp2_raw) = conn.receive_response().await?;

        // Update session preauth hash with response.
        session_hasher.update(&resp2_raw);

        if resp2_header.command != Command::SessionSetup {
            return Err(Error::invalid_data(format!(
                "expected SessionSetup response, got {:?}",
                resp2_header.command
            )));
        }

        if resp2_header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: resp2_header.status,
                command: Command::SessionSetup,
            });
        }

        // Parse the final response.
        let mut cursor2 = ReadCursor::new(&resp2_body);
        let setup_resp2 = SessionSetupResponse::unpack(&mut cursor2)?;

        let session_id = resp2_header.session_id;
        conn.set_session_id(session_id);

        // Get the session key from NTLM.
        let session_key = auth
            .session_key()
            .ok_or_else(|| Error::Auth {
                message: "NTLM did not produce a session key".to_string(),
            })?
            .to_vec();

        // Determine signing algorithm.
        let gmac_negotiated = params.gmac_negotiated;
        let signing_algorithm = algorithm_for_dialect(params.dialect, gmac_negotiated);

        // Derive keys for SMB 3.x, or use session key directly for SMB 2.x.
        let (signing_key, encryption_key, decryption_key) = match params.dialect {
            Dialect::Smb3_0 | Dialect::Smb3_0_2 => {
                let keys = derive_session_keys(&session_key, params.dialect, None, 128);
                (keys.signing_key, Some(keys.encryption_key), Some(keys.decryption_key))
            }
            Dialect::Smb3_1_1 => {
                // Key length: 256 bits if AES-256 cipher OR GMAC signing is
                // negotiated (GMAC uses AES-256-GCM internally, needs 32-byte key).
                let key_len_bits = match params.cipher {
                    Some(super::connection::Cipher::Aes256Ccm)
                    | Some(super::connection::Cipher::Aes256Gcm) => 256,
                    _ if params.gmac_negotiated => 256,
                    _ => 128,
                };
                let keys = derive_session_keys(
                    &session_key,
                    Dialect::Smb3_1_1,
                    Some(session_hasher.value()),
                    key_len_bits,
                );
                (keys.signing_key, Some(keys.encryption_key), Some(keys.decryption_key))
            }
            _ => {
                // SMB 2.x: use session key directly for signing.
                (session_key.clone(), None, None)
            }
        };

        // Determine if we should sign.
        let should_sign = params.signing_required
            || !setup_resp2.session_flags.is_guest()
                && !setup_resp2.session_flags.is_null();

        let should_encrypt = setup_resp2.session_flags.encrypt_data();

        // Activate signing on the connection.
        if should_sign {
            conn.activate_signing(signing_key.clone(), signing_algorithm);
        }

        Ok(Session {
            session_id,
            signing_key,
            encryption_key,
            decryption_key,
            signing_algorithm,
            should_sign,
            should_encrypt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::{pack_message, Connection, NegotiatedParams};
    use crate::msg::header::Header;
    use crate::msg::session_setup::{SessionFlags, SessionSetupResponse};
    use crate::pack::Guid;
    use crate::transport::MockTransport;
    use crate::types::flags::Capabilities;
    use crate::types::status::NtStatus;
    use crate::types::{Command, Dialect, SessionId};
    use std::sync::Arc;

    /// Build a session setup response with the given status and session ID.
    fn build_session_setup_response(
        status: NtStatus,
        session_id: SessionId,
        security_buffer: Vec<u8>,
        session_flags: SessionFlags,
    ) -> Vec<u8> {
        let mut h = Header::new_request(Command::SessionSetup);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;
        h.session_id = session_id;

        let body = SessionSetupResponse {
            session_flags,
            security_buffer,
        };

        pack_message(&h, &body)
    }

    /// Build a minimal NTLM challenge message (Type 2).
    ///
    /// This is a stripped-down challenge that the NtlmAuthenticator can parse.
    fn build_ntlm_challenge() -> Vec<u8> {
        let mut buf = Vec::new();

        // Signature (8 bytes)
        buf.extend_from_slice(b"NTLMSSP\0");
        // MessageType = 2 (4 bytes)
        buf.extend_from_slice(&2u32.to_le_bytes());
        // TargetNameFields: Len=0, MaxLen=0, Offset=56
        buf.extend_from_slice(&0u16.to_le_bytes()); // Len
        buf.extend_from_slice(&0u16.to_le_bytes()); // MaxLen
        buf.extend_from_slice(&56u32.to_le_bytes()); // Offset
        // NegotiateFlags
        let flags: u32 = 0x0000_0001 // UNICODE
            | 0x0000_0200  // NTLM
            | 0x0008_0000  // EXTENDED_SESSIONSECURITY
            | 0x0080_0000  // TARGET_INFO
            | 0x2000_0000  // 128
            | 0x4000_0000  // KEY_EXCH
            | 0x8000_0000  // 56
            | 0x0000_0010  // SIGN
            | 0x0000_0020; // SEAL
        buf.extend_from_slice(&flags.to_le_bytes());
        // ServerChallenge (8 bytes)
        buf.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        // Reserved (8 bytes)
        buf.extend_from_slice(&[0u8; 8]);

        // TargetInfoFields: Len, MaxLen, Offset (will be at offset 56 + target_name_len)
        // Build target info: just MsvAvEOL
        let target_info = build_av_eol();
        let ti_offset = 56u32; // right after the fixed header
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // Len
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // MaxLen
        buf.extend_from_slice(&ti_offset.to_le_bytes()); // Offset

        // Ensure we're at offset 56 (pad if needed).
        while buf.len() < 56 {
            buf.push(0);
        }

        // Target info data
        buf.extend_from_slice(&target_info);

        buf
    }

    /// Build an AV_PAIR list with just MsvAvEOL.
    fn build_av_eol() -> Vec<u8> {
        let mut buf = Vec::new();
        // MsvAvEOL: AvId=0, AvLen=0
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf
    }

    #[tokio::test]
    async fn session_setup_stores_session_id() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0xDEAD_BEEF);

        // Queue the two session setup responses.
        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));
        mock.queue_response(build_session_setup_response(
            NtStatus::SUCCESS,
            session_id,
            vec![],
            SessionFlags(0),
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        // Set up negotiate params (pretend we already negotiated).
        // We need to call negotiate or set params manually.
        // Let's also queue a negotiate response first.
        // Actually, let's set params directly.
        set_test_params(&mut conn, Dialect::Smb2_0_2);

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();
        assert_eq!(session.session_id, session_id);
    }

    #[tokio::test]
    async fn session_setup_derives_signing_key() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0x1234);

        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));
        mock.queue_response(build_session_setup_response(
            NtStatus::SUCCESS,
            session_id,
            vec![],
            SessionFlags(0),
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        set_test_params(&mut conn, Dialect::Smb2_0_2);

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();
        assert!(!session.signing_key.is_empty());
    }

    #[tokio::test]
    async fn session_setup_activates_signing() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0x5678);

        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));
        mock.queue_response(build_session_setup_response(
            NtStatus::SUCCESS,
            session_id,
            vec![],
            SessionFlags(0),
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        set_test_params(&mut conn, Dialect::Smb2_0_2);

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();
        assert!(session.should_sign);
        assert_eq!(session.signing_algorithm, SigningAlgorithm::HmacSha256);
    }

    #[tokio::test]
    async fn session_setup_error_on_auth_failure() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0x9999);

        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));
        // Auth fails on second round.
        mock.queue_response(build_session_setup_response(
            NtStatus::LOGON_FAILURE,
            session_id,
            vec![],
            SessionFlags(0),
        ));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        set_test_params(&mut conn, Dialect::Smb2_0_2);

        let result = Session::setup(&mut conn, "user", "badpass", "").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Protocol {
                    status: NtStatus::LOGON_FAILURE,
                    ..
                }
            ),
            "expected LOGON_FAILURE, got: {err}"
        );
    }

    /// Helper: set fake negotiated params on a connection.
    fn set_test_params(conn: &mut Connection, dialect: Dialect) {
        conn.set_test_params(NegotiatedParams {
            dialect,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(),
            gmac_negotiated: false,
            cipher: None,
        });
    }
}
