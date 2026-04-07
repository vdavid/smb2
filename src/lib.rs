#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Pure-Rust SMB2/3 client library with pipelined I/O.
//!
//! No C dependencies, no FFI. Built for speed — pipelined reads/writes
//! match native OS SMB performance on metadata-heavy operations and
//! close the gap on bulk transfers.
