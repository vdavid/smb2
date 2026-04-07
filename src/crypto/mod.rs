//! Cryptographic operations for SMB2/3: signing, encryption, key derivation, and compression.
//!
//! Most users don't need this module directly -- [`SmbClient`](crate::SmbClient)
//! handles signing and encryption automatically.

pub mod signing;
pub mod encryption;
pub mod kdf;
pub mod compression;
