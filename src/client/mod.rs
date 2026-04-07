//! High-level SMB2 client API.
//!
//! Provides [`Connection`] for low-level message exchange, [`Session`] for
//! authenticated sessions, [`Tree`] for share access with file operations,
//! and [`Pipeline`] for batched concurrent operations.

pub mod connection;
pub mod pipeline;
pub mod session;
pub mod tree;

pub use connection::{Cipher, Connection, NegotiatedParams};
pub use pipeline::{Op, OpResult, Pipeline};
pub use session::Session;
pub use tree::{DirectoryEntry, FileInfo, Tree};
