//! Wire format message structs for SMB2/3.
//!
//! Each sub-module corresponds to one SMB2 command type with its
//! request and response structures.
//!
//! Most users don't need this module directly -- use [`SmbClient`](crate::SmbClient)
//! for high-level file operations.

pub mod cancel;
pub mod change_notify;
pub mod close;
pub mod create;
pub mod echo;
pub mod flush;
pub mod header;
pub mod ioctl;
pub mod lock;
pub mod logoff;
pub mod negotiate;
pub mod oplock_break;
pub mod query_directory;
pub mod query_info;
pub mod read;
pub mod session_setup;
pub mod set_info;
pub mod transform;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod write;

pub use header::{ErrorResponse, Header, PROTOCOL_ID};
