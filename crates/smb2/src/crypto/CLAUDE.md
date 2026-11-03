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

Four ciphers, negotiated during NEGOTIATE (`client/connection.rs` `negotiated_cipher`):
- AES-128-CCM (11-byte nonce) -- the only cipher on SMB 3.0 / 3.0.2, granted by the server's `SMB2_GLOBAL_CAP_ENCRYPTION`
- AES-128-GCM (12-byte nonce) -- SMB 3.1.1
- AES-256-CCM (11-byte nonce) -- SMB 3.1.1
- AES-256-GCM (12-byte nonce) -- SMB 3.1.1

On 3.1.1 the server picks one from our `SMB2_ENCRYPTION_CAPABILITIES`, and only if NEGOTIATE carried `SMB2_GLOBAL_CAP_ENCRYPTION`: Samba reads the context only then, so without the bit it picks none (#32). No cipher means no encryption keys and no encryption; a session or share that demands it fails with `Error::EncryptionUnavailable`. ❌ Never fall back to a cipher of our own: the server decrypts nothing with it, and that fallback is what let the encryption fixtures pass in plaintext for months.

Nonces come from a `NonceGenerator` with a monotonic u64 counter. Nonce reuse breaks GCM catastrophically -- the counter must never reset within a session.

AAD is the TRANSFORM_HEADER bytes 20..52 (Nonce + OriginalMessageSize + Reserved + Flags + SessionId). The auth tag goes into the Signature field at bytes 4..20.

## Key derivation (SP800-108)

`derive_session_keys(gss_key, dialect, preauth_hash, cipher)` produces three keys (signing, encryption, decryption) using HMAC-SHA256 in counter mode. `gss_key` is the whole key the authentication produced: NTLM's 16-byte `ExportedSessionKey`, or the Kerberos subkey (32 bytes for an AES-256 enctype).

- **SMB 3.0/3.0.2**: Fixed ASCII label/context pairs (for example, `"SMB2AESCMAC\0"` / `"SmbSign\0"`)
- **SMB 3.1.1**: New labels (`"SMBSigningKey\0"`) with preauth hash (64-byte SHA-512) as context
- **The signing key is always 128 bits, from `Session.SessionKey`** (`session_key`: the first 16 bytes, zero-padded). ❌ Never derive it at the cipher's length: a 32-byte signing key failed every session with a server that picked AES-256, encrypting or not (#32).
- **AES-256 encryption keys on 3.1.1 come from the FULL key** (`Session.FullSessionKey`, MS-SMB2 § 3.2.5.3.1), at 256 bits; everything else uses the first 16 bytes. With NTLM the two are the same bytes, so only Kerberos can catch a regression here; `aes_256_cipher_keys_come_from_the_full_session_key` pins it on the mock. Verified against Windows Server 2022 AD DS with global encryption and AES-256-GCM only (2026-11-03): a 32-byte subkey, encrypted write/read/delete pass, and deriving from the first 16 bytes instead fails at the first encrypted request (`tests/CLAUDE.md` § AWS integration tests).

`PreauthHasher` computes `SHA-512(prev_hash || message_bytes)` incrementally over negotiate and session-setup wire bytes. Cloned per session (spec requires per-session hash).

## Key decisions

- **Labels include `\0` terminator**: Matches smb-rs and the spec's Label field definitions. The double-null (label `\0` + separator `0x00`) is correct.
- **GMAC uses AES-128, not AES-256**: Despite the signing algorithm name containing "256", the actual GMAC implementation uses AES-128-GCM. The "256" in the spec refers to the GMAC algorithm ID, not the key size. Signing keys are always 16 bytes.

## Gotchas

- **GMAC nonce has a role bit**: Client signs with role=0, server with role=1. Verify uses role=1 (server). Same message+key produces different signatures for client vs server.
- **GMAC nonce also has a CANCEL bit, and forgetting it fails silently**: byte 8 bit 1, set when the message's command is `Command::Cancel` (MS-SMB2 § 3.1.4.1). ❌ Both call sites must pass it from the command, never a hardcoded `false`: an outgoing CANCEL signed without it is refused by a GMAC-negotiating server, and a CANCEL has no success response, so the client sees nothing and believes it cancelled a request the server is still holding. On a QNAP TS-464 that left every cancelled CHANGE_NOTIFY registered and the directory watch stopped delivering events (2026-08-03). The receive side reads the same bit back for the server's rejection response, the one frame that would otherwise say so.
- **Verification never trusts the `SIGNED` flag, and the tag compare is constant-time**: `prepare_sub_frame` verifies every response on a signed session except interim `STATUS_PENDING` and oplock breaks; an unsigned frame fails on its zero signature. `verify_signature` compares with `ctutils::CtEq` and refuses with `Error::SignatureInvalid` (`ErrorKind::SignatureInvalid`), `SignatureFailure::Missing` for an all-zero signature field and `Mismatch` otherwise; ❌ never `InvalidData`, which callers read as a malformed reply. ❌ Don't reintroduce `!=` on the tag. See `AGENTS.md` pitfall 29.
- **Signing and encryption are mutually exclusive on the wire**: When encryption is active, the signature field is zeroed (AEAD provides auth). Never sign AND encrypt.
- **Nonce counter must not be reused**: `NonceGenerator` panics on u64 overflow (unreachable in practice). Each session gets its own generator.
- **HMAC-SHA256 for signing accepts any key length**: Unlike CMAC/GMAC which require exactly 16 bytes. HMAC pads/hashes the key internally.
