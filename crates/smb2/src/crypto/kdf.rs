//! SP800-108 key derivation and preauthentication integrity hashing for SMB2/3.
//!
//! SMB 3.x uses NIST SP800-108 KDF in counter mode with HMAC-SHA256 as the PRF
//! to derive signing, encryption, and decryption keys from the session key.
//!
//! SMB 3.1.1 additionally requires a preauthentication integrity hash (SHA-512)
//! computed over the raw wire bytes of NEGOTIATE and SESSION_SETUP exchanges,
//! which feeds into the KDF as the "context" parameter.

use crate::crypto::encryption::Cipher;
use crate::types::Dialect;
use digest::{Digest, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;

/// Derive a key using SP800-108 KDF in counter mode with HMAC-SHA256.
///
/// This implements the algorithm from NIST SP800-108 section 5.1 as required
/// by MS-SMB2 section 3.1.4.2. The counter width ('r') is 32 bits, and the
/// PRF is HMAC-SHA256.
///
/// # Arguments
///
/// * `key` - The key to derive from (the session key from authentication).
/// * `label` - Label string (including null terminator).
/// * `context` - Context string or preauth hash (including null terminator for
///   string contexts).
/// * `key_length_bits` - Desired output key length in bits (128 or 256).
pub fn sp800_108_kdf(key: &[u8], label: &[u8], context: &[u8], key_length_bits: u32) -> Vec<u8> {
    let iterations = key_length_bits.div_ceil(256);
    let mut result = Vec::with_capacity((iterations * 32) as usize);

    for i in 1..=iterations {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");

        // counter (32-bit big-endian)
        mac.update(&i.to_be_bytes());
        // label
        mac.update(label);
        // separator byte 0x00
        mac.update(&[0x00]);
        // context
        mac.update(context);
        // L = key length in bits (32-bit big-endian)
        mac.update(&key_length_bits.to_be_bytes());

        result.extend_from_slice(&mac.finalize().into_bytes());
    }

    result.truncate((key_length_bits / 8) as usize);
    result
}

/// Derived session keys for signing, encryption, and decryption.
///
/// `Debug` shows the keys as `***`.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Key used to sign outgoing messages.
    pub signing_key: Vec<u8>,
    /// Key used to encrypt outgoing messages.
    pub encryption_key: Vec<u8>,
    /// Key used to decrypt incoming messages.
    pub decryption_key: Vec<u8>,
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::crypto::Redacted;
        f.debug_struct("DerivedKeys")
            .field("signing_key", &Redacted)
            .field("encryption_key", &Redacted)
            .field("decryption_key", &Redacted)
            .finish()
    }
}

/// `Session.SessionKey` from the key the authentication protocol produced
/// (MS-SMB2 § 3.2.5.3.1): its first 16 bytes, right-padded with zeros if it
/// is shorter.
///
/// NTLM's key is exactly 16 bytes, so this is that key. Kerberos hands over
/// the whole subkey (32 bytes for an AES-256 enctype), and everything except
/// AES-256 encryption uses only these first 16 bytes of it.
pub fn session_key(gss_key: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let n = gss_key.len().min(16);
    key[..n].copy_from_slice(&gss_key[..n]);
    key
}

/// Derive session keys for the given dialect (MS-SMB2 § 3.2.5.3.1).
///
/// `gss_key` is the key the authentication protocol produced, in full: the
/// NTLM `ExportedSessionKey` or the Kerberos subkey. `cipher` is the
/// connection's negotiated cipher (`Connection.CipherId`).
///
/// Two rules here are easy to get wrong, and both broke AES-256 once:
///
/// - **The signing key is always 128 bits**, derived from [`session_key`]
///   (`Session.SigningKey` is "a 128-bit key"). Only the encryption and
///   decryption keys follow the cipher.
/// - **AES-256 keys on 3.1.1 come from the FULL key**
///   (`Session.FullSessionKey`), not its first 16 bytes. With NTLM the two
///   are the same 16 bytes; with Kerberos and an AES-256 enctype they aren't,
///   and deriving from the truncated key gives keys the server doesn't have.
///
/// For SMB 3.0 and 3.0.2, the context is a fixed ASCII string and the cipher
/// is always AES-128-CCM, whatever `cipher` says. For SMB 3.1.1, the context
/// is the preauthentication integrity hash value (64 bytes from SHA-512).
///
/// # Panics
///
/// Panics if `dialect` is SMB 3.1.1 and `preauth_hash` is `None`.
/// Panics if `dialect` is not in the SMB 3.x family.
pub fn derive_session_keys(
    gss_key: &[u8],
    dialect: Dialect,
    preauth_hash: Option<&[u8; 64]>,
    cipher: Option<Cipher>,
) -> DerivedKeys {
    assert!(
        matches!(
            dialect,
            Dialect::Smb3_0 | Dialect::Smb3_0_2 | Dialect::Smb3_1_1
        ),
        "Key derivation is only applicable for the SMB 3.x dialect family"
    );

    let (signing_label, signing_context): (&[u8], &[u8]);
    let (enc_label, enc_context): (&[u8], &[u8]);
    let (dec_label, dec_context): (&[u8], &[u8]);

    if dialect == Dialect::Smb3_1_1 {
        let hash = preauth_hash
            .expect("SMB 3.1.1 requires a preauthentication integrity hash for key derivation");
        // SMB 3.1.1 labels include null terminator (matches smb-rs and
        // the MS-SMB2 spec's Label field definitions)
        signing_label = b"SMBSigningKey\0";
        signing_context = hash.as_slice();
        enc_label = b"SMBC2SCipherKey\0";
        enc_context = hash.as_slice();
        dec_label = b"SMBS2CCipherKey\0";
        dec_context = hash.as_slice();
    } else {
        // SMB 3.0 and 3.0.2
        signing_label = b"SMB2AESCMAC\0";
        signing_context = b"SmbSign\0";
        enc_label = b"SMB2AESCCM\0";
        enc_context = b"ServerIn \0";
        dec_label = b"SMB2AESCCM\0";
        dec_context = b"ServerOut\0";
    }

    let session_key = session_key(gss_key);
    let aes_256 = dialect == Dialect::Smb3_1_1
        && matches!(cipher, Some(Cipher::Aes256Ccm | Cipher::Aes256Gcm));
    let (cipher_key, cipher_bits): (&[u8], u32) = if aes_256 {
        (gss_key, 256)
    } else {
        (&session_key, 128)
    };

    DerivedKeys {
        signing_key: sp800_108_kdf(&session_key, signing_label, signing_context, 128),
        encryption_key: sp800_108_kdf(cipher_key, enc_label, enc_context, cipher_bits),
        decryption_key: sp800_108_kdf(cipher_key, dec_label, dec_context, cipher_bits),
    }
}

/// Running hash over negotiate and session-setup exchange bytes.
///
/// Used as the "context" parameter to the KDF for SMB 3.1.1. The hash
/// algorithm is SHA-512, producing a 64-byte value.
///
/// The hash is computed incrementally:
/// 1. Initialize with 64 zero bytes
/// 2. `update()` with negotiate request raw bytes
/// 3. `update()` with negotiate response raw bytes
/// 4. (Clone for session hash)
/// 5. `update()` with session setup request raw bytes
/// 6. `update()` with session setup response raw bytes
/// 7. Repeat 5-6 for each SESSION_SETUP round-trip
///
/// Each `update()` computes: `hash = SHA-512(previous_hash || message_bytes)`
pub struct PreauthHasher {
    hash: [u8; 64],
}

impl PreauthHasher {
    /// Create a new hasher initialized with 64 zero bytes.
    pub fn new() -> Self {
        Self { hash: [0u8; 64] }
    }

    /// Update the hash with a message's raw wire bytes.
    ///
    /// Computes `hash = SHA-512(previous_hash || message_bytes)`.
    pub fn update(&mut self, message_bytes: &[u8]) {
        let mut hasher = Sha512::new();
        hasher.update(self.hash);
        hasher.update(message_bytes);
        self.hash.copy_from_slice(&hasher.finalize());
    }

    /// Get the current hash value (64 bytes).
    pub fn value(&self) -> &[u8; 64] {
        &self.hash
    }
}

impl Default for PreauthHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for PreauthHasher {
    fn clone(&self) -> Self {
        Self { hash: self.hash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SP800-108 KDF tests
    // ========================================================================

    #[test]
    fn kdf_128_bit_output_is_16_bytes() {
        let key = [0xAA; 16];
        let result = sp800_108_kdf(&key, b"label\0", b"context\0", 128);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn kdf_256_bit_output_is_32_bytes() {
        let key = [0xBB; 16];
        let result = sp800_108_kdf(&key, b"label\0", b"context\0", 256);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn kdf_is_deterministic() {
        let key = [0x42; 16];
        let label = b"TestLabel\0";
        let context = b"TestContext\0";
        let r1 = sp800_108_kdf(&key, label, context, 128);
        let r2 = sp800_108_kdf(&key, label, context, 128);
        assert_eq!(r1, r2);
    }

    #[test]
    fn kdf_different_labels_produce_different_keys() {
        let key = [0x42; 16];
        let context = b"ctx\0";
        let k1 = sp800_108_kdf(&key, b"LabelA\0", context, 128);
        let k2 = sp800_108_kdf(&key, b"LabelB\0", context, 128);
        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_different_contexts_produce_different_keys() {
        let key = [0x42; 16];
        let label = b"label\0";
        let k1 = sp800_108_kdf(&key, label, b"ContextA\0", 128);
        let k2 = sp800_108_kdf(&key, label, b"ContextB\0", 128);
        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_different_session_keys_produce_different_derived_keys() {
        let label = b"SMB2AESCMAC\0";
        let context = b"SmbSign\0";
        let k1 = sp800_108_kdf(&[0x11; 16], label, context, 128);
        let k2 = sp800_108_kdf(&[0x22; 16], label, context, 128);
        assert_ne!(k1, k2);
    }

    /// Verify KDF output against a manually computed value.
    ///
    /// For a single iteration (128-bit output), the KDF computes:
    /// HMAC-SHA256(key, 0x00000001 || label || 0x00 || context || 0x00000080)
    /// and takes the first 16 bytes.
    #[test]
    fn kdf_known_vector_single_iteration() {
        let key = [0x00u8; 16];
        let label = b"SMB2AESCMAC\0";
        let context = b"SmbSign\0";

        // Manually compute the expected value.
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&1u32.to_be_bytes()); // counter = 1
        mac.update(label); // label
        mac.update(&[0x00]); // separator
        mac.update(context); // context
        mac.update(&128u32.to_be_bytes()); // L = 128
        let full = mac.finalize().into_bytes();
        let expected = &full[..16];

        let result = sp800_108_kdf(&key, label, context, 128);
        assert_eq!(result.as_slice(), expected);
    }

    /// Verify that 256-bit KDF uses two iterations and concatenates correctly.
    #[test]
    fn kdf_known_vector_two_iterations() {
        let key = [0xFFu8; 16];
        let label = b"TestLabel\0";
        let context = b"TestCtx\0";

        // Compute iteration 1
        let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
        mac1.update(&1u32.to_be_bytes());
        mac1.update(label);
        mac1.update(&[0x00]);
        mac1.update(context);
        mac1.update(&256u32.to_be_bytes());
        let block1 = mac1.finalize().into_bytes();

        // 256 bits = 32 bytes = exactly one HMAC-SHA256 block, so only one
        // iteration is needed. But let's verify with the formula:
        // ceil(256 / 256) = 1 iteration. So 256-bit also needs just one.
        let result = sp800_108_kdf(&key, label, context, 256);
        assert_eq!(result.len(), 32);
        assert_eq!(result.as_slice(), block1.as_slice());
    }

    // ========================================================================
    // derive_session_keys tests
    // ========================================================================

    #[test]
    fn derive_keys_smb3_0_uses_legacy_labels() {
        let session_key = [0x42; 16];
        let keys = derive_session_keys(&session_key, Dialect::Smb3_0, None, None);

        // Verify each key matches what we'd get calling KDF directly with the
        // SMB 3.0 label/context pairs.
        assert_eq!(
            keys.signing_key,
            sp800_108_kdf(&session_key, b"SMB2AESCMAC\0", b"SmbSign\0", 128)
        );
        assert_eq!(
            keys.encryption_key,
            sp800_108_kdf(&session_key, b"SMB2AESCCM\0", b"ServerIn \0", 128)
        );
        assert_eq!(
            keys.decryption_key,
            sp800_108_kdf(&session_key, b"SMB2AESCCM\0", b"ServerOut\0", 128)
        );
    }

    #[test]
    fn derive_keys_smb3_0_2_uses_legacy_labels() {
        let session_key = [0x42; 16];
        let keys = derive_session_keys(&session_key, Dialect::Smb3_0_2, None, None);

        assert_eq!(
            keys.signing_key,
            sp800_108_kdf(&session_key, b"SMB2AESCMAC\0", b"SmbSign\0", 128)
        );
        assert_eq!(
            keys.encryption_key,
            sp800_108_kdf(&session_key, b"SMB2AESCCM\0", b"ServerIn \0", 128)
        );
        assert_eq!(
            keys.decryption_key,
            sp800_108_kdf(&session_key, b"SMB2AESCCM\0", b"ServerOut\0", 128)
        );
    }

    #[test]
    fn derive_keys_smb3_1_1_uses_new_labels_with_preauth_hash() {
        let session_key = [0x42; 16];
        let preauth_hash = [0xAB; 64];
        let keys = derive_session_keys(&session_key, Dialect::Smb3_1_1, Some(&preauth_hash), None);

        assert_eq!(
            keys.signing_key,
            sp800_108_kdf(&session_key, b"SMBSigningKey\0", &preauth_hash, 128)
        );
        assert_eq!(
            keys.encryption_key,
            sp800_108_kdf(&session_key, b"SMBC2SCipherKey\0", &preauth_hash, 128)
        );
        assert_eq!(
            keys.decryption_key,
            sp800_108_kdf(&session_key, b"SMBS2CCipherKey\0", &preauth_hash, 128)
        );
    }

    /// `Session.SigningKey` is 128 bits whatever the cipher (MS-SMB2
    /// § 3.2.1.3): a 32-byte one failed every AES-256 session with "AES-128-GMAC
    /// requires a 16-byte key" (reported in #32).
    #[test]
    fn derive_keys_smb3_1_1_256_bit() {
        let session_key = [0x42; 16];
        let preauth_hash = [0xCD; 64];
        for cipher in [Cipher::Aes256Gcm, Cipher::Aes256Ccm] {
            let keys = derive_session_keys(
                &session_key,
                Dialect::Smb3_1_1,
                Some(&preauth_hash),
                Some(cipher),
            );

            assert_eq!(
                keys.signing_key,
                sp800_108_kdf(&session_key, b"SMBSigningKey\0", &preauth_hash, 128)
            );
            assert_eq!(
                keys.encryption_key,
                sp800_108_kdf(&session_key, b"SMBC2SCipherKey\0", &preauth_hash, 256)
            );
            assert_eq!(
                keys.decryption_key,
                sp800_108_kdf(&session_key, b"SMBS2CCipherKey\0", &preauth_hash, 256)
            );
        }
    }

    /// Kerberos with an AES-256 enctype hands over a 32-byte subkey. AES-256
    /// encryption keys come from all of it (`Session.FullSessionKey`); the
    /// signing key comes from its first 16 bytes (`Session.SessionKey`).
    #[test]
    fn aes_256_cipher_keys_come_from_the_full_session_key() {
        let full_key: Vec<u8> = (0u8..32).collect();
        let preauth_hash = [0xCD; 64];
        let keys = derive_session_keys(
            &full_key,
            Dialect::Smb3_1_1,
            Some(&preauth_hash),
            Some(Cipher::Aes256Gcm),
        );

        assert_eq!(
            keys.signing_key,
            sp800_108_kdf(&full_key[..16], b"SMBSigningKey\0", &preauth_hash, 128)
        );
        assert_eq!(
            keys.encryption_key,
            sp800_108_kdf(&full_key, b"SMBC2SCipherKey\0", &preauth_hash, 256)
        );
        assert_eq!(
            keys.decryption_key,
            sp800_108_kdf(&full_key, b"SMBS2CCipherKey\0", &preauth_hash, 256)
        );
    }

    /// Below AES-256 (and on every dialect before 3.1.1) only the first 16
    /// bytes of a long Kerberos key take part.
    #[test]
    fn a_long_key_is_cut_to_16_bytes_below_aes_256() {
        let full_key: Vec<u8> = (0u8..32).collect();
        let preauth_hash = [0xCD; 64];
        let cases = [
            (
                Dialect::Smb3_1_1,
                Some(&preauth_hash),
                Some(Cipher::Aes128Gcm),
            ),
            (Dialect::Smb3_1_1, Some(&preauth_hash), None),
            // A 3.0.2 connection is AES-128-CCM whatever the caller passes.
            (Dialect::Smb3_0_2, None, Some(Cipher::Aes256Gcm)),
        ];
        let all = |k: DerivedKeys| (k.signing_key, k.encryption_key, k.decryption_key);
        for (dialect, hash, cipher) in cases {
            let keys = all(derive_session_keys(&full_key, dialect, hash, cipher));
            let cut = all(derive_session_keys(&full_key[..16], dialect, hash, cipher));
            assert_eq!(keys, cut, "{dialect:?} {cipher:?}");
            assert_eq!(keys.1.len(), 16, "{dialect:?} {cipher:?}");
        }
    }

    #[test]
    fn session_key_is_the_first_16_bytes_right_padded_with_zeros() {
        let long: Vec<u8> = (1u8..=32).collect();
        assert_eq!(session_key(&long).as_slice(), &long[..16]);
        let mut padded = [0u8; 16];
        padded[..8].copy_from_slice(&[7; 8]);
        assert_eq!(session_key(&[7; 8]), padded);
    }

    #[test]
    fn derive_keys_all_three_are_different() {
        let session_key = [0x42; 16];
        let keys = derive_session_keys(&session_key, Dialect::Smb3_0, None, None);

        assert_ne!(keys.signing_key, keys.encryption_key);
        assert_ne!(keys.signing_key, keys.decryption_key);
        assert_ne!(keys.encryption_key, keys.decryption_key);
    }

    #[test]
    #[should_panic(expected = "preauthentication integrity hash")]
    fn derive_keys_smb3_1_1_panics_without_preauth_hash() {
        let session_key = [0x42; 16];
        derive_session_keys(&session_key, Dialect::Smb3_1_1, None, None);
    }

    #[test]
    #[should_panic(expected = "SMB 3.x dialect family")]
    fn derive_keys_panics_for_smb2() {
        let session_key = [0x42; 16];
        derive_session_keys(&session_key, Dialect::Smb2_0_2, None, None);
    }

    // ========================================================================
    // PreauthHasher tests
    // ========================================================================

    #[test]
    fn preauth_hasher_starts_with_64_zero_bytes() {
        let hasher = PreauthHasher::new();
        assert_eq!(hasher.value(), &[0u8; 64]);
    }

    #[test]
    fn preauth_hasher_default_equals_new() {
        let h1 = PreauthHasher::new();
        let h2 = PreauthHasher::default();
        assert_eq!(h1.value(), h2.value());
    }

    #[test]
    fn preauth_hasher_update_changes_hash() {
        let mut hasher = PreauthHasher::new();
        let initial = *hasher.value();
        hasher.update(b"negotiate request bytes");
        assert_ne!(hasher.value(), &initial);
    }

    #[test]
    fn preauth_hasher_two_updates_differ_from_one() {
        let mut hasher1 = PreauthHasher::new();
        hasher1.update(b"message1");

        let mut hasher2 = PreauthHasher::new();
        hasher2.update(b"message1");
        hasher2.update(b"message2");

        assert_ne!(hasher1.value(), hasher2.value());
    }

    #[test]
    fn preauth_hasher_is_deterministic() {
        let mut h1 = PreauthHasher::new();
        h1.update(b"negotiate request");
        h1.update(b"negotiate response");

        let mut h2 = PreauthHasher::new();
        h2.update(b"negotiate request");
        h2.update(b"negotiate response");

        assert_eq!(h1.value(), h2.value());
    }

    #[test]
    fn preauth_hasher_empty_update_changes_hash() {
        // SHA-512(64_zeros || empty) != 64_zeros
        let mut hasher = PreauthHasher::new();
        let initial = *hasher.value();
        hasher.update(b"");
        assert_ne!(hasher.value(), &initial);
    }

    #[test]
    fn preauth_hasher_known_value() {
        // Verify against direct SHA-512 computation.
        let mut hasher = PreauthHasher::new();
        hasher.update(b"test");

        let mut expected_hasher = Sha512::new();
        expected_hasher.update([0u8; 64]);
        expected_hasher.update(b"test");
        let expected = expected_hasher.finalize();

        assert_eq!(hasher.value().as_slice(), expected.as_slice());
    }

    #[test]
    fn preauth_hasher_chained_known_value() {
        // Two updates: hash1 = SHA-512(zeros || msg1), hash2 = SHA-512(hash1 || msg2)
        let mut hasher = PreauthHasher::new();
        hasher.update(b"negotiate");
        hasher.update(b"response");

        // Compute manually
        let mut h = Sha512::new();
        h.update([0u8; 64]);
        h.update(b"negotiate");
        let hash1: [u8; 64] = h.finalize().into();

        let mut h2 = Sha512::new();
        h2.update(hash1);
        h2.update(b"response");
        let hash2: [u8; 64] = h2.finalize().into();

        assert_eq!(hasher.value(), &hash2);
    }

    #[test]
    fn preauth_hasher_clone_is_independent() {
        let mut hasher = PreauthHasher::new();
        hasher.update(b"negotiate request");
        hasher.update(b"negotiate response");

        // Clone for session hash (spec step 4)
        let mut session_hasher = hasher.clone();
        session_hasher.update(b"session setup request");

        // Original should not be affected
        assert_ne!(hasher.value(), session_hasher.value());
    }

    #[test]
    fn preauth_hasher_output_is_64_bytes() {
        let mut hasher = PreauthHasher::new();
        hasher.update(b"some data");
        assert_eq!(hasher.value().len(), 64);
    }

    /// Full end-to-end test: preauth hash feeds into KDF for SMB 3.1.1.
    #[test]
    fn preauth_hash_feeds_into_kdf() {
        // Simulate the protocol flow
        let mut conn_hasher = PreauthHasher::new();
        conn_hasher.update(b"negotiate request bytes");
        conn_hasher.update(b"negotiate response bytes");

        let mut session_hasher = conn_hasher.clone();
        session_hasher.update(b"session setup request bytes");
        session_hasher.update(b"session setup response bytes");

        let session_key = [0x42; 16];
        let keys = derive_session_keys(
            &session_key,
            Dialect::Smb3_1_1,
            Some(session_hasher.value()),
            Some(Cipher::Aes128Gcm),
        );

        // Keys should all be 16 bytes and different from each other
        assert_eq!(keys.signing_key.len(), 16);
        assert_eq!(keys.encryption_key.len(), 16);
        assert_eq!(keys.decryption_key.len(), 16);
        assert_ne!(keys.signing_key, keys.encryption_key);
        assert_ne!(keys.signing_key, keys.decryption_key);
        assert_ne!(keys.encryption_key, keys.decryption_key);
    }

    #[test]
    fn derived_keys_debug_output_hides_the_keys() {
        let keys = DerivedKeys {
            signing_key: vec![0xAB; 16],
            encryption_key: vec![0xAB; 16],
            decryption_key: vec![0xAB; 16],
        };
        let printed = format!("{keys:?}");
        assert!(!printed.contains("171"), "{printed}");
        assert!(printed.contains("signing_key: ***"), "{printed}");
    }
}
