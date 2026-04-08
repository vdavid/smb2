//! Kerberos authentication support.
//!
//! Implements the cryptographic operations needed for Kerberos authentication
//! (etypes 17, 18, 23): string-to-key, key derivation, AES-CTS encryption,
//! RC4-HMAC encryption, and checksum computation.

pub mod crypto;
