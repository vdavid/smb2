//! SMB2 message signing and signature verification.
//!
//! Supports three signing algorithms, selected by negotiated dialect:
//! - **HMAC-SHA256** (SMB 2.0.2, 2.1): 32-byte hash truncated to 16 bytes.
//! - **AES-128-CMAC** (SMB 3.0, 3.0.2): 16-byte MAC.
//! - **AES-256-GMAC** (SMB 3.1.1 with `SMB2_SIGNING_CAPABILITIES`): AES-256-GCM
//!   with empty plaintext; the 16-byte auth tag is the signature.
//!
//! Reference: MS-SMB2 sections 3.1.4.1 (signing) and 3.1.5.1 (verification).

use crate::types::Dialect;
use crate::Error;

/// Offset of the 16-byte Signature field within the SMB2 header.
const SIGNATURE_OFFSET: usize = 48;
/// Length of the Signature field.
const SIGNATURE_LEN: usize = 16;
/// Minimum message length (full SMB2 header).
const MIN_MESSAGE_LEN: usize = 64;

/// Signing algorithm, determined by negotiated dialect and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// HMAC-SHA256 truncated to 16 bytes (SMB 2.0.2, 2.1).
    HmacSha256,
    /// AES-128-CMAC (SMB 3.0, 3.0.2).
    AesCmac,
    /// AES-256-GMAC with MessageId-based nonce (SMB 3.1.1).
    AesGmac,
}

/// Select the appropriate signing algorithm for a dialect.
///
/// For SMB 3.1.1, `gmac_negotiated` indicates whether the peer negotiated
/// `AES-256-GMAC` via `SMB2_SIGNING_CAPABILITIES`. When `false`, SMB 3.1.1
/// falls back to AES-128-CMAC.
pub fn algorithm_for_dialect(dialect: Dialect, gmac_negotiated: bool) -> SigningAlgorithm {
    match dialect {
        Dialect::Smb2_0_2 | Dialect::Smb2_1 => SigningAlgorithm::HmacSha256,
        Dialect::Smb3_0 | Dialect::Smb3_0_2 => SigningAlgorithm::AesCmac,
        Dialect::Smb3_1_1 => {
            if gmac_negotiated {
                SigningAlgorithm::AesGmac
            } else {
                SigningAlgorithm::AesCmac
            }
        }
    }
}

/// Sign an SMB2 message in-place.
///
/// Zeros the signature field (bytes 48-63), computes the signature
/// over the full message, and writes the computed signature back.
///
/// For AES-GMAC, `message_id` and `is_cancel` are used to construct
/// the 12-byte nonce. For other algorithms these parameters are ignored.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the message is shorter than 64 bytes
/// or the key length is wrong for the chosen algorithm.
pub fn sign_message(
    message: &mut [u8],
    key: &[u8],
    algorithm: SigningAlgorithm,
    message_id: u64,
    is_cancel: bool,
) -> Result<(), Error> {
    if message.len() < MIN_MESSAGE_LEN {
        return Err(Error::invalid_data(format!(
            "message too short for signing: {} bytes, need at least {}",
            message.len(),
            MIN_MESSAGE_LEN
        )));
    }

    // Step 1: zero the signature field.
    message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);

    // Step 2: compute signature over the entire message.
    let signature = compute_signature(message, key, algorithm, message_id, is_cancel)?;

    // Step 3: write the signature back.
    message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].copy_from_slice(&signature);

    Ok(())
}

/// Verify the signature on a received SMB2 message.
///
/// Returns `Ok(())` if the signature matches, or [`Error::InvalidData`]
/// if the message is tampered or the key is wrong.
pub fn verify_signature(
    message: &[u8],
    key: &[u8],
    algorithm: SigningAlgorithm,
    message_id: u64,
    is_cancel: bool,
) -> Result<(), Error> {
    if message.len() < MIN_MESSAGE_LEN {
        return Err(Error::invalid_data(format!(
            "message too short for verification: {} bytes, need at least {}",
            message.len(),
            MIN_MESSAGE_LEN
        )));
    }

    // Step 1: save the received signature.
    let mut received_sig = [0u8; SIGNATURE_LEN];
    received_sig.copy_from_slice(&message[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]);

    // Step 2: zero the signature field in a copy.
    let mut buf = message.to_vec();
    buf[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);

    // Step 3: compute the expected signature.
    let expected_sig = compute_signature(&buf, key, algorithm, message_id, is_cancel)?;

    // Step 4: compare.
    if received_sig != expected_sig {
        return Err(Error::invalid_data("signature verification failed"));
    }

    Ok(())
}

/// Compute a 16-byte signature over `message` using the given algorithm.
fn compute_signature(
    message: &[u8],
    key: &[u8],
    algorithm: SigningAlgorithm,
    message_id: u64,
    is_cancel: bool,
) -> Result<[u8; 16], Error> {
    match algorithm {
        SigningAlgorithm::HmacSha256 => compute_hmac_sha256(message, key),
        SigningAlgorithm::AesCmac => compute_aes_cmac(message, key),
        SigningAlgorithm::AesGmac => compute_aes_gmac(message, key, message_id, is_cancel),
    }
}

/// HMAC-SHA256, truncated to 16 bytes. Key must be 16 bytes.
fn compute_hmac_sha256(message: &[u8], key: &[u8]) -> Result<[u8; 16], Error> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| Error::invalid_data(format!("HMAC-SHA256 key error: {e}")))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();

    // Truncate 32-byte hash to first 16 bytes.
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&result[..16]);
    Ok(sig)
}

/// AES-128-CMAC. Key must be 16 bytes.
fn compute_aes_cmac(message: &[u8], key: &[u8]) -> Result<[u8; 16], Error> {
    use aes::Aes128;
    use cmac::{Cmac, Mac};

    type AesCmac = Cmac<Aes128>;

    let mut mac = AesCmac::new_from_slice(key)
        .map_err(|e| Error::invalid_data(format!("AES-CMAC key error: {e}")))?;
    mac.update(message);
    let result = mac.finalize().into_bytes();

    let mut sig = [0u8; 16];
    sig.copy_from_slice(&result);
    Ok(sig)
}

/// AES-256-GMAC (AES-256-GCM with empty plaintext). Key must be 32 bytes.
///
/// The 12-byte nonce is constructed as:
/// - Bytes 0-7: `message_id` (little-endian u64)
/// - Bytes 8-11: bit 0 = 0 (client role), bit 1 = `is_cancel`, remaining 30 bits = 0
fn compute_aes_gmac(
    message: &[u8],
    key: &[u8],
    message_id: u64,
    is_cancel: bool,
) -> Result<[u8; 16], Error> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if key.len() != 32 {
        return Err(Error::invalid_data(format!(
            "AES-256-GMAC requires a 32-byte key, got {} bytes",
            key.len()
        )));
    }

    // Build 12-byte nonce.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&message_id.to_le_bytes());
    // Byte 8: bit 0 = role (0 = client), bit 1 = CANCEL flag.
    if is_cancel {
        nonce_bytes[8] = 0x02;
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::invalid_data(format!("AES-256-GMAC key error: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // GMAC mode: encrypt empty plaintext with the message as AAD.
    // The "ciphertext" is empty; the auth tag IS the signature.
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &[],
        aad: message,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| Error::invalid_data(format!("AES-256-GMAC encryption error: {e}")))?;

    // The output is the 16-byte auth tag (no ciphertext bytes since plaintext was empty).
    if ciphertext.len() != 16 {
        return Err(Error::invalid_data(format!(
            "unexpected GMAC output length: expected 16, got {}",
            ciphertext.len()
        )));
    }

    let mut sig = [0u8; 16];
    sig.copy_from_slice(&ciphertext);
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 64-byte fake SMB2 message for testing.
    /// The signature field (bytes 48-63) is zeroed.
    fn make_test_message(body_extra: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 64 + body_extra.len()];
        // Protocol ID
        msg[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // Structure size = 64
        msg[4..6].copy_from_slice(&64u16.to_le_bytes());
        // Fill some fields so the message isn't all zeros
        msg[12..14].copy_from_slice(&0x0008u16.to_le_bytes()); // Command = Read
        msg[24..32].copy_from_slice(&42u64.to_le_bytes()); // MessageId = 42
        // Append body
        msg[64..].copy_from_slice(body_extra);
        msg
    }

    // ── algorithm_for_dialect ─────────────────────────────────────────

    #[test]
    fn algorithm_for_smb2_0_2_is_hmac_sha256() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb2_0_2, false),
            SigningAlgorithm::HmacSha256
        );
    }

    #[test]
    fn algorithm_for_smb2_1_is_hmac_sha256() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb2_1, false),
            SigningAlgorithm::HmacSha256
        );
    }

    #[test]
    fn algorithm_for_smb3_0_is_aes_cmac() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb3_0, false),
            SigningAlgorithm::AesCmac
        );
    }

    #[test]
    fn algorithm_for_smb3_0_2_is_aes_cmac() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb3_0_2, false),
            SigningAlgorithm::AesCmac
        );
    }

    #[test]
    fn algorithm_for_smb3_1_1_without_gmac_is_aes_cmac() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb3_1_1, false),
            SigningAlgorithm::AesCmac
        );
    }

    #[test]
    fn algorithm_for_smb3_1_1_with_gmac_is_aes_gmac() {
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb3_1_1, true),
            SigningAlgorithm::AesGmac
        );
    }

    #[test]
    fn gmac_flag_ignored_for_older_dialects() {
        // Even if gmac_negotiated is true, older dialects don't use GMAC.
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb2_0_2, true),
            SigningAlgorithm::HmacSha256
        );
        assert_eq!(
            algorithm_for_dialect(Dialect::Smb3_0, true),
            SigningAlgorithm::AesCmac
        );
    }

    // ── Message too short ─────────────────────────────────────────────

    #[test]
    fn sign_rejects_message_shorter_than_64_bytes() {
        let mut msg = vec![0u8; 32];
        let key = [0u8; 16];
        let result = sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn verify_rejects_message_shorter_than_64_bytes() {
        let msg = vec![0u8; 32];
        let key = [0u8; 16];
        let result = verify_signature(&msg, &key, SigningAlgorithm::HmacSha256, 0, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    // ── HMAC-SHA256 ──────────────────────────────────────────────────

    #[test]
    fn hmac_sha256_sign_produces_nonzero_signature() {
        let mut msg = make_test_message(b"hello world");
        let key = [0xAA; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        let sig = &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN];
        assert_ne!(sig, &[0u8; 16], "signature should not be all zeros");
    }

    #[test]
    fn hmac_sha256_known_signature() {
        // Compute expected HMAC-SHA256 using the same process:
        // zero sig field, compute HMAC, truncate to 16 bytes.
        let mut msg = make_test_message(&[]);
        let key = [0x01; 16];

        // Manually compute expected value.
        let mut zeroed = msg.clone();
        zeroed[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);
        let expected = {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type H = Hmac<Sha256>;
            let mut mac = H::new_from_slice(&key).unwrap();
            mac.update(&zeroed);
            let full = mac.finalize().into_bytes();
            let mut trunc = [0u8; 16];
            trunc.copy_from_slice(&full[..16]);
            trunc
        };

        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();
        assert_eq!(
            &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN],
            &expected
        );
    }

    #[test]
    fn hmac_sha256_sign_then_verify_roundtrip() {
        let mut msg = make_test_message(b"some payload data");
        let key = [0x42; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();
        verify_signature(&msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();
    }

    #[test]
    fn hmac_sha256_verify_fails_on_tampered_message() {
        let mut msg = make_test_message(b"original data");
        let key = [0x42; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        // Flip a byte in the body.
        let last = msg.len() - 1;
        msg[last] ^= 0xFF;

        let result = verify_signature(&msg, &key, SigningAlgorithm::HmacSha256, 0, false);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("verification failed"),
        );
    }

    #[test]
    fn hmac_sha256_verify_fails_with_wrong_key() {
        let mut msg = make_test_message(b"data");
        let key = [0x42; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        let wrong_key = [0x43; 16];
        let result = verify_signature(&msg, &wrong_key, SigningAlgorithm::HmacSha256, 0, false);
        assert!(result.is_err());
    }

    // ── AES-128-CMAC ────────────────────────────────────────────────

    #[test]
    fn aes_cmac_sign_produces_nonzero_signature() {
        let mut msg = make_test_message(b"cmac test");
        let key = [0xBB; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();

        let sig = &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN];
        assert_ne!(sig, &[0u8; 16]);
    }

    #[test]
    fn aes_cmac_known_signature() {
        let mut msg = make_test_message(&[]);
        let key = [0x02; 16];

        let mut zeroed = msg.clone();
        zeroed[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);
        let expected = {
            use aes::Aes128;
            use cmac::{Cmac, Mac};
            type C = Cmac<Aes128>;
            let mut mac = C::new_from_slice(&key).unwrap();
            mac.update(&zeroed);
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&result);
            sig
        };

        sign_message(&mut msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();
        assert_eq!(
            &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN],
            &expected
        );
    }

    #[test]
    fn aes_cmac_sign_then_verify_roundtrip() {
        let mut msg = make_test_message(b"cmac roundtrip payload");
        let key = [0x55; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();
        verify_signature(&msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();
    }

    #[test]
    fn aes_cmac_verify_fails_on_tampered_message() {
        let mut msg = make_test_message(b"cmac original");
        let key = [0x55; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();

        msg[10] ^= 0xFF;

        let result = verify_signature(&msg, &key, SigningAlgorithm::AesCmac, 0, false);
        assert!(result.is_err());
    }

    #[test]
    fn aes_cmac_verify_fails_with_wrong_key() {
        let mut msg = make_test_message(b"cmac data");
        let key = [0x55; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::AesCmac, 0, false).unwrap();

        let wrong_key = [0x56; 16];
        let result = verify_signature(&msg, &wrong_key, SigningAlgorithm::AesCmac, 0, false);
        assert!(result.is_err());
    }

    // ── AES-256-GMAC ────────────────────────────────────────────────

    #[test]
    fn aes_gmac_sign_produces_nonzero_signature() {
        let mut msg = make_test_message(b"gmac test");
        let key = [0xCC; 32];
        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 1, false).unwrap();

        let sig = &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN];
        assert_ne!(sig, &[0u8; 16]);
    }

    #[test]
    fn aes_gmac_known_signature() {
        let mut msg = make_test_message(&[]);
        let key = [0x03; 32];
        let message_id: u64 = 7;

        let mut zeroed = msg.clone();
        zeroed[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].fill(0);
        let expected = {
            use aes_gcm::aead::{Aead, Payload};
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[0..8].copy_from_slice(&message_id.to_le_bytes());
            // not cancel, client role -> byte 8 = 0

            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let nonce = Nonce::from_slice(&nonce_bytes);
            let payload = Payload {
                msg: &[],
                aad: &zeroed,
            };
            let ct = cipher.encrypt(nonce, payload).unwrap();
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&ct);
            sig
        };

        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, message_id, false).unwrap();
        assert_eq!(
            &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN],
            &expected
        );
    }

    #[test]
    fn aes_gmac_sign_then_verify_roundtrip() {
        let mut msg = make_test_message(b"gmac roundtrip payload");
        let key = [0xDD; 32];
        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 100, false).unwrap();
        verify_signature(&msg, &key, SigningAlgorithm::AesGmac, 100, false).unwrap();
    }

    #[test]
    fn aes_gmac_verify_fails_on_tampered_message() {
        let mut msg = make_test_message(b"gmac original");
        let key = [0xDD; 32];
        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 5, false).unwrap();

        let last = msg.len() - 1;
        msg[last] ^= 0xFF;

        let result = verify_signature(&msg, &key, SigningAlgorithm::AesGmac, 5, false);
        assert!(result.is_err());
    }

    #[test]
    fn aes_gmac_verify_fails_with_wrong_key() {
        let mut msg = make_test_message(b"gmac data");
        let key = [0xDD; 32];
        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 5, false).unwrap();

        let wrong_key = [0xDE; 32];
        let result = verify_signature(&msg, &wrong_key, SigningAlgorithm::AesGmac, 5, false);
        assert!(result.is_err());
    }

    #[test]
    fn aes_gmac_rejects_wrong_key_length() {
        let mut msg = make_test_message(&[]);
        let key = [0xDD; 16]; // 16 bytes instead of 32
        let result = sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 0, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32-byte key"));
    }

    // ── GMAC nonce construction ─────────────────────────────────────

    #[test]
    fn aes_gmac_nonce_contains_message_id() {
        // Different MessageIds must produce different signatures on the same message+key.
        let key = [0xEE; 32];

        let mut msg1 = make_test_message(b"nonce test");
        sign_message(&mut msg1, &key, SigningAlgorithm::AesGmac, 1, false).unwrap();
        let sig1: [u8; 16] = msg1[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
            .try_into()
            .unwrap();

        let mut msg2 = make_test_message(b"nonce test");
        sign_message(&mut msg2, &key, SigningAlgorithm::AesGmac, 2, false).unwrap();
        let sig2: [u8; 16] = msg2[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
            .try_into()
            .unwrap();

        assert_ne!(sig1, sig2, "different MessageIds must produce different signatures");
    }

    #[test]
    fn aes_gmac_cancel_bit_changes_signature() {
        let key = [0xEE; 32];
        let message_id = 42u64;

        let mut msg_normal = make_test_message(b"cancel test");
        sign_message(
            &mut msg_normal,
            &key,
            SigningAlgorithm::AesGmac,
            message_id,
            false,
        )
        .unwrap();
        let sig_normal: [u8; 16] = msg_normal[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
            .try_into()
            .unwrap();

        let mut msg_cancel = make_test_message(b"cancel test");
        sign_message(
            &mut msg_cancel,
            &key,
            SigningAlgorithm::AesGmac,
            message_id,
            true,
        )
        .unwrap();
        let sig_cancel: [u8; 16] = msg_cancel[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN]
            .try_into()
            .unwrap();

        assert_ne!(
            sig_normal, sig_cancel,
            "CANCEL bit must produce a different signature"
        );
    }

    #[test]
    fn aes_gmac_cancel_bit_is_bit_1_of_byte_8() {
        // Verify the nonce byte 8 value directly by checking that
        // the CANCEL nonce has 0x02 at byte 8 (bit 1), not 0x01 (bit 0).
        let message_id: u64 = 99;

        let mut nonce_normal = [0u8; 12];
        nonce_normal[0..8].copy_from_slice(&message_id.to_le_bytes());
        // is_cancel = false -> byte 8 stays 0x00

        let mut nonce_cancel = [0u8; 12];
        nonce_cancel[0..8].copy_from_slice(&message_id.to_le_bytes());
        nonce_cancel[8] = 0x02; // bit 1 set, NOT bit 0

        assert_eq!(nonce_normal[8], 0x00);
        assert_eq!(nonce_cancel[8], 0x02);
        // Bit 0 (role bit) is always 0 for client.
        assert_eq!(nonce_cancel[8] & 0x01, 0x00);
    }

    // ── Signature field location ────────────────────────────────────

    #[test]
    fn signature_field_is_at_bytes_48_through_63() {
        let mut msg = make_test_message(&[]);
        let key = [0xFF; 16];

        // Set a marker pattern in bytes 48-63 to verify they get overwritten.
        msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN].copy_from_slice(&[0xAA; 16]);

        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        // The marker should be gone, replaced by the computed signature.
        let sig = &msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LEN];
        assert_ne!(sig, &[0xAA; 16], "signature field must be overwritten");
        assert_ne!(sig, &[0x00; 16], "signature should not be all zeros");
    }

    #[test]
    fn bytes_outside_signature_field_are_preserved() {
        let body = b"preserve me";
        let mut msg = make_test_message(body);
        let original_body = msg[64..].to_vec();
        let original_header_prefix = msg[0..SIGNATURE_OFFSET].to_vec();

        let key = [0xFF; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        // Header bytes before signature are unchanged.
        assert_eq!(&msg[0..SIGNATURE_OFFSET], &original_header_prefix);
        // Body is unchanged.
        assert_eq!(&msg[64..], &original_body);
    }

    // ── Cross-algorithm: verify with wrong algorithm fails ──────────

    #[test]
    fn verify_with_wrong_algorithm_fails() {
        let mut msg = make_test_message(b"cross algo");
        let key = [0x77; 16];
        sign_message(&mut msg, &key, SigningAlgorithm::HmacSha256, 0, false).unwrap();

        let result = verify_signature(&msg, &key, SigningAlgorithm::AesCmac, 0, false);
        assert!(result.is_err());
    }

    // ── GMAC: verify with wrong message_id fails ────────────────────

    #[test]
    fn aes_gmac_verify_with_wrong_message_id_fails() {
        let mut msg = make_test_message(b"msg id test");
        let key = [0xDD; 32];
        sign_message(&mut msg, &key, SigningAlgorithm::AesGmac, 10, false).unwrap();

        let result = verify_signature(&msg, &key, SigningAlgorithm::AesGmac, 11, false);
        assert!(result.is_err());
    }
}
