#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure-Rust SMB2/3 client library with pipelined I/O.
//!
//! No C dependencies, no FFI. Pipelined reads/writes fill the credit window
//! so downloads run ~10-25x faster than sequential SMB clients.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use smb2::{SmbClient, ClientConfig};
//!
//! # async fn example() -> Result<(), smb2::Error> {
//! let mut client = smb2::connect("192.168.1.100:445", "user", "pass").await?;
//!
//! // List shares
//! let shares = client.list_shares().await?;
//!
//! // Connect to a share
//! let share = client.connect_share("Documents").await?;
//!
//! // List files
//! let entries = client.list_directory(&share, "projects/").await?;
//! for entry in &entries {
//!     println!("{} ({} bytes)", entry.name, entry.size);
//! }
//!
//! // Read a file
//! let data = client.read_file(&share, "report.pdf").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! - [`client`] -- High-level API: [`SmbClient`], [`Tree`], [`Pipeline`].
//!   This is what most users need.
//! - [`error`] -- Error types and NTSTATUS mapping.
//! - [`msg`] -- Wire format message structs (advanced/internal use).
//! - [`pack`] -- Binary serialization primitives (advanced/internal use).
//! - [`transport`] -- Transport trait and TCP implementation (advanced/internal use).
//! - [`crypto`] -- Signing and encryption (advanced/internal use).
//! - [`auth`] -- NTLM authentication (advanced/internal use).
//! - [`rpc`] -- Named pipe RPC for share enumeration (advanced/internal use).
//! - [`types`] -- Protocol newtypes and flag types (advanced/internal use).

pub mod auth;
pub mod client;
pub mod crypto;
pub mod error;
pub mod msg;
pub mod pack;
pub mod rpc;
pub mod transport;
pub mod types;

// ── Re-exports: the simple-case imports ────────────────────────────────

// Error types
pub use error::{Error, ErrorKind, Result};

// High-level client
pub use client::{connect, ClientConfig, SmbClient};

// Streaming I/O
pub use client::stream::{FileDownload, FileUpload, Progress};

// Tree and file types
pub use client::tree::{DirectoryEntry, FileInfo, FsInfo, Tree};

// Pipeline
pub use client::pipeline::{Op, OpResult, Pipeline};

// Connection-level types (useful for advanced users)
pub use client::connection::NegotiatedParams;
pub use client::session::Session;

// File watching
pub use client::watcher::{FileNotifyAction, FileNotifyEvent, Watcher};

// Share enumeration
pub use rpc::srvsvc::ShareInfo;
