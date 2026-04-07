//! Authentication mechanisms for SMB2.
//!
//! Currently supports NTLM authentication (MS-NLMP).

pub mod ntlm;

pub use ntlm::{NtlmAuthenticator, NtlmCredentials};
