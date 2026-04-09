# Auth -- NTLM and Kerberos authentication

NTLMv2 and Kerberos authentication for SMB2 session setup.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | Module exports |
| `der.rs` | Shared ASN.1/DER primitives (TLV encode/decode) |
| `ntlm.rs` | `NtlmAuthenticator` -- 3-message NTLM exchange |
| `spnego.rs` | SPNEGO NegTokenInit/NegTokenResp wrapping |
| `kerberos/mod.rs` | Kerberos module root, re-exports authenticator |
| `kerberos/authenticator.rs` | `KerberosAuthenticator` -- full AS + TGS + AP-REQ flow |
| `kerberos/crypto.rs` | AES-CTS, RC4-HMAC, string-to-key, key derivation |
| `kerberos/messages.rs` | ASN.1/DER encoding/decoding for Kerberos messages |
| `kerberos/kdc.rs` | KDC transport client (UDP/TCP with fallback) |

## NTLM exchange

1. `negotiate()` -- builds NEGOTIATE_MESSAGE (Type 1) with default flags
2. Server sends CHALLENGE_MESSAGE (Type 2) with server challenge and target info
3. `authenticate(&challenge_bytes)` -- builds AUTHENTICATE_MESSAGE (Type 3) with NTLMv2 response

Only NTLMv2 is supported. NTLMv1 is insecure and not implemented.

## Kerberos exchange

`KerberosAuthenticator` performs the full Kerberos flow in three steps:

1. **AS exchange** (client -> KDC): derive user key from password, build PA-ENC-TIMESTAMP + PA-PAC-REQUEST, send AS-REQ, parse AS-REP, decrypt enc-part with user key to get TGT + AS session key.
2. **TGS exchange** (client -> KDC): build AP-REQ wrapping TGT + authenticator (encrypted with AS session key), send TGS-REQ for `cifs/hostname`, parse TGS-REP, decrypt enc-part with AS session key to get service ticket + TGS session key.
3. **AP-REQ construction**: build Authenticator with subkey, encrypt with TGS session key, build AP-REQ with service ticket, wrap in SPNEGO NegTokenInit.

The flow differs from NTLM: Kerberos contacts the KDC directly (async, network I/O), then produces a single token for SESSION_SETUP (usually 1 round-trip with the SMB server).

### Key usage numbers (RFC 4120 section 7.5.1)

- 1: PA-ENC-TIMESTAMP encryption
- 3: AS-REP EncKDCRepPart decryption
- 6: TGS-REQ PA-TGS-REQ Authenticator cksum (body checksum)
- 7: AP-REQ Authenticator encryption
- 8: TGS-REP EncKDCRepPart decryption (tries 8 first, falls back to 9)

### Encryption types supported

- AES-256-CTS-HMAC-SHA1-96 (etype 18) -- preferred
- AES-128-CTS-HMAC-SHA1-96 (etype 17)
- RC4-HMAC (etype 23) -- legacy

### Key derivation constants (RFC 3961)

Three subkeys are derived from each base key + usage number:
- **Ke** = DK(key, usage || 0xAA) -- encryption subkey, used for AES-CTS
- **Ki** = DK(key, usage || 0x55) -- integrity subkey, used for HMAC inside encrypt/decrypt
- **Kc** = DK(key, usage || 0x99) -- checksum subkey, used for standalone checksum/MIC

Ki and Kc are NOT the same key. Ki is for the HMAC that's appended to ciphertext in the encrypt() function. Kc is for standalone operations like the body checksum in the TGS-REQ Authenticator.

### Kerberos wire encryption format (AES)

1. Derive Ke (with 0xAA) and Ki (with 0x55) from base key + usage
2. Generate 16-byte random confounder
3. plaintext' = confounder || plaintext
4. ciphertext = AES-CTS(Ke, iv=0, plaintext')
5. hmac = HMAC-SHA1-96(Ki, plaintext') -- 12 bytes
6. output = ciphertext || hmac

## NTLM key derivation flow

1. `NTOWFv2`: `HMAC-MD5(MD4(password_utf16), uppercase(username) + domain)`
2. `NTProofStr`: `HMAC-MD5(NTOWFv2, server_challenge + client_blob)`
3. `SessionBaseKey`: `HMAC-MD5(NTOWFv2, NTProofStr)`
4. If KEY_EXCH flag: generate random session key, RC4-encrypt with SessionBaseKey
5. `ExportedSessionKey` feeds into SP800-108 KDF (in `crypto/kdf.rs`)

## MIC computation

Modern servers include `MsvAvTimestamp` in the challenge target info, which triggers MIC validation. When present:
1. Add `MsvAvFlags` with bit 0x2 (MIC present) to the target info
2. Build the AUTHENTICATE_MESSAGE with a zeroed 16-byte MIC field at offset 72
3. Compute `HMAC-MD5(ExportedSessionKey, negotiate_msg || challenge_msg || authenticate_msg)`
4. Patch the MIC into bytes 72..88

The authenticator retains raw bytes of NEGOTIATE and CHALLENGE messages for this computation.

## Key decisions

- **`getrandom` for random values**: Client challenge, random session key, nonces, and confounders use `getrandom` (OS CSPRNG).
- **`test_random_session_key` override**: Tests can inject a deterministic session key for reproducibility. Never used in production.
- **Subkey in AP-REQ Authenticator**: The Kerberos authenticator includes a random subkey, which becomes the SMB session key. This provides forward secrecy.
- **No full `authenticate()` unit tests**: The full flow requires a real KDC. Unit tests cover individual steps (encrypt/decrypt roundtrip, message encoding, etype parsing). Integration tests with Docker are planned.

## Gotchas

- **Retain raw challenge bytes for MIC (NTLM)**: The MIC is computed over the exact wire bytes of all three messages.
- **RC4 for key exchange is inline (NTLM)**: ~15 lines of RC4 implementation.
- **MsvAvTimestamp presence changes behavior (NTLM)**: Without it, no MIC is computed. With it, MIC is mandatory.
- **NTLMv1 not supported**: No fallback.
- **Target info modification (NTLM)**: The client modifies the server's target info before including it in the client blob.
- **TGS-REP key usage ambiguity (Kerberos)**: RFC 4120 says key usage 8 for TGS-REP encrypted with session key, but some KDCs use 9. The authenticator tries 8 first, falls back to 9.
- **KDC_ERR_PREAUTH_REQUIRED handling (Kerberos)**: First AS-REQ without pre-auth gets error 25. The authenticator extracts supported etypes from the e-data (ETYPE-INFO2) and retries with pre-authentication.
- **DER primitives in `auth::der`**: Core DER encoding/decoding helpers (`der_length`, `der_tlv`, `parse_der_length`, `parse_der_tlv`) live in `auth/der.rs` and are shared by `spnego.rs` and `kerberos/messages.rs`. Type-specific helpers (INTEGER, GeneralString, etc.) stay in their respective modules.

## Kerberos key design decisions (from end-to-end testing)

- **MS Kerberos OID (`1.2.840.48018.1.2.2`)**: Windows AD requires the Microsoft Kerberos OID in SPNEGO NegTokenInit, not the standard RFC 4120 OID. Both are included in mechTypes, with MS OID first.
- **Key usage 11 for SPNEGO AP-REQ Authenticator**: Standard RFC 4120 uses key usage 7 for AP-REQ Authenticator encryption. Windows expects key usage 11 when the AP-REQ is wrapped in SPNEGO (per MS-KILE). Using 7 causes `KRB_AP_ERR_MODIFIED`.
- **RC4 session keys**: Even when AES-256 is used for Kerberos exchanges, the TGS may return an RC4-HMAC session key (etype 23). The authenticator detects the actual etype from the TGS-REP and uses the correct decryption.
- **Raw ticket pass-through**: The service ticket bytes must be sent to the SMB server exactly as received from the KDC. Re-encoding the ticket from parsed fields produces different DER and causes `KRB_AP_ERR_MODIFIED`. The `Ticket` struct carries `raw_bytes` for this.
- **GSS-API wrapping**: The AP-REQ in SPNEGO NegTokenInit must include the GSS-API OID header (`0x60 len OID ap-req`), not just the raw AP-REQ bytes.
- **Mutual auth handling**: Windows AD returns `STATUS_MORE_PROCESSING_REQUIRED` with an SPNEGO `AcceptIncomplete` containing an AP-REP. The client processes the AP-REP but does NOT send a second SESSION_SETUP (Windows returns `STATUS_INVALID_PARAMETER` if you do).

## Known tech debt (Kerberos)

- ~~DER helpers duplicated between `spnego.rs` and `kerberos/messages.rs`~~ (resolved: shared `auth/der.rs`)
- ~~`kerberos/authenticator.rs` mixes crypto wrappers with protocol flow~~ (resolved: `kerberos_encrypt`, `kerberos_decrypt`, `etype_from_i32`, and `generate_random_key` moved to `kerberos/crypto.rs`)
- `#![allow(rustdoc::broken_intra_doc_links)]` hack in `kerberos/messages.rs`
