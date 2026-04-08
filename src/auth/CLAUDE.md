# Auth -- NTLM authentication

NTLMv2 authentication for SMB2 session setup. Kerberos is not implemented (deferred).

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `Auth` trait definition |
| `ntlm.rs` | `NtlmAuthenticator` -- 3-message NTLM exchange |

## NTLM exchange

1. `negotiate()` -- builds NEGOTIATE_MESSAGE (Type 1) with default flags
2. Server sends CHALLENGE_MESSAGE (Type 2) with server challenge and target info
3. `authenticate(&challenge_bytes)` -- builds AUTHENTICATE_MESSAGE (Type 3) with NTLMv2 response

Only NTLMv2 is supported. NTLMv1 is insecure and not implemented.

## Key derivation flow

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

- **`getrandom` for random values**: Client challenge and random session key use `getrandom` (OS CSPRNG), not time-seeded LCG.
- **`test_random_session_key` override**: Tests can inject a deterministic session key for reproducibility. Never used in production.

## Gotchas

- **Retain raw challenge bytes for MIC**: The MIC is computed over the exact wire bytes of all three messages. Parsing and re-serializing would produce different bytes. `NtlmAuthenticator` stores the raw challenge.
- **RC4 for key exchange is inline**: ~15 lines of RC4 implementation. Too small to justify a dependency, and the `rc4` crate has inconsistent API versions.
- **MsvAvTimestamp presence changes behavior**: Without it, no MIC is computed. With it, MIC is mandatory. Missing MIC when required causes auth failure on modern servers.
- **NTLMv1 not supported**: No fallback. If the server only accepts NTLMv1, auth fails.
- **Target info modification**: The client modifies the server's target info (adds MsvAvFlags, resets MsvAvEOL position) before including it in the client blob.
