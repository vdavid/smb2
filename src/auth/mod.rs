//! Authentication mechanisms for SMB2.
//!
//! Currently supports NTLM authentication (MS-NLMP).
//!
//! Most users don't need this module directly -- [`SmbClient`](crate::SmbClient)
//! handles authentication during [`connect`](crate::connect).

pub mod ntlm;

pub use ntlm::{NtlmAuthenticator, NtlmCredentials};
