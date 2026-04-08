# Crypto -- signing, encryption, key derivation, compression

Handles all cryptographic operations. Most users don't touch this directly -- `Session::setup` and `Connection` use it automatically.

## Key files

| File | Purpose |
|---|---|
| `signing.rs` | Sign/verify messages. Three algorithms: HMAC-SHA256, AES-CMAC, AES-GMAC |
| `encryption.rs` | Encrypt/decrypt messages. Four ciphers: AES-128/256-CCM, AES-128/256-GCM |
| `kdf.rs` | SP800-108 KDF + `PreauthHasher` (SHA-512 running hash) |
| `compression.rs` | LZ4 compression for SMB 3.1.1 |

## Signing algorithms

| Algorithm | Dialect | Key size |
|---|---|---|
| HMAC-SHA256 (truncated to 16 bytes) | SMB 2.0.2, 2.1 | any |
| AES-128-CMAC | SMB 3.0, 3.0.2, 3.1.1 (fallback) | 16 bytes |
| AES-128-GMAC | SMB 3.1.1 (with `SMB2_SIGNING_CAPABILITIES`) | 16 bytes |

GMAC is AES-128-GCM with empty plaintext. The auth tag IS the signature. The 12-byte nonce encodes `MessageId` (bytes 0-7), a role bit (byte 8 bit 0: 0=client, 1=server), and a cancel flag (byte 8 bit 1).

## Encryption

Four ciphers, negotiated during NEGOTIATE:
- AES-128-CCM (11-byte nonce) -- SMB 3.0+
- AES-128-GCM (12-byte nonce) -- SMB 3.0+
- AES-256-CCM (11-byte nonce) -- SMB 3.1.1
- AES-256-GCM (12-byte nonce) -- SMB 3.1.1

Nonces come from a `NonceGenerator` with a monotonic u64 counter. Nonce reuse breaks GCM catastrophically -- the counter must never reset within a session.

AAD is the TRANSFORM_HEADER bytes 20..52 (Nonce + OriginalMessageSize + Reserved + Flags + SessionId). The auth tag goes into the Signature field at bytes 4..20.

## Key derivation (SP800-108)

`derive_session_keys` produces three keys (signing, encryption, decryption) from the NTLM session key using HMAC-SHA256 in counter mode.

- **SMB 3.0/3.0.2**: Fixed ASCII label/context pairs (for example, `"SMB2AESCMAC\0"` / `"SmbSign\0"`)
- **SMB 3.1.1**: New labels (`"SMBSigningKey\0"`) with preauth hash (64-byte SHA-512) as context

`PreauthHasher` computes `SHA-512(prev_hash || message_bytes)` incrementally over negotiate and session-setup wire bytes. Cloned per session (spec requires per-session hash).

## Key decisions

- **Labels include `\0` terminator**: Matches smb-rs and the spec's Label field definitions. The double-null (label `\0` + separator `0x00`) is correct.
- **GMAC uses AES-128, not AES-256**: Despite the signing algorithm name containing "256", the actual GMAC implementation uses AES-128-GCM. The "256" in the spec refers to the GMAC algorithm ID, not the key size. Signing keys are always 16 bytes.

## Gotchas

- **GMAC nonce has a role bit**: Client signs with role=0, server with role=1. Verify uses role=1 (server). Same message+key produces different signatures for client vs server.
- **Signing and encryption are mutually exclusive on the wire**: When encryption is active, the signature field is zeroed (AEAD provides auth). Never sign AND encrypt.
- **Nonce counter must not be reused**: `NonceGenerator` panics on u64 overflow (unreachable in practice). Each session gets its own generator.
- **HMAC-SHA256 for signing accepts any key length**: Unlike CMAC/GMAC which require exactly 16 bytes. HMAC pads/hashes the key internally.
