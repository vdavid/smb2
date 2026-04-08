//! Bitflag types for SMB2/3 protocol fields.

use std::ops::{BitAnd, BitOr, BitOrAssign};

// ── Macro to reduce boilerplate for flag types ──────────────────────────

macro_rules! impl_flags {
    ($name:ident, $inner:ty) => {
        impl $name {
            /// Create a new flags value from a raw integer.
            #[inline]
            pub const fn new(raw: $inner) -> Self {
                Self(raw)
            }

            /// Return the raw bits.
            #[inline]
            pub const fn bits(&self) -> $inner {
                self.0
            }

            /// Check whether a particular flag bit is set.
            #[inline]
            pub const fn contains(&self, flag: $inner) -> bool {
                self.0 & flag == flag
            }

            /// Set a flag bit.
            #[inline]
            pub fn set(&mut self, flag: $inner) {
                self.0 |= flag;
            }

            /// Clear a flag bit.
            #[inline]
            pub fn clear(&mut self, flag: $inner) {
                self.0 &= !flag;
            }
        }

        impl BitOr for $name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl BitAnd for $name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl BitOrAssign for $name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }
    };
}

// ── HeaderFlags ─────────────────────────────────────────────────────────

/// SMB2 packet header flags (32-bit field from MS-SMB2 2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderFlags(pub u32);

impl HeaderFlags {
    /// The message is a response rather than a request.
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    /// The message is an async SMB2 header.
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    /// The message is part of a compounded chain.
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    /// The message is signed.
    pub const SIGNED: u32 = 0x0000_0008;
    /// Priority value mask (SMB 3.1.1).
    pub const PRIORITY_MASK: u32 = 0x0000_0070;
    /// The command is a DFS operation.
    pub const DFS_OPERATIONS: u32 = 0x1000_0000;
    /// The command is a replay operation (SMB 3.x).
    pub const REPLAY_OPERATION: u32 = 0x2000_0000;

    /// Returns `true` if this is a response (server-to-redirector).
    #[inline]
    pub fn is_response(&self) -> bool {
        self.contains(Self::SERVER_TO_REDIR)
    }

    /// Returns `true` if the async flag is set.
    #[inline]
    pub fn is_async(&self) -> bool {
        self.contains(Self::ASYNC_COMMAND)
    }

    /// Returns `true` if the related-operations flag is set.
    #[inline]
    pub fn is_related(&self) -> bool {
        self.contains(Self::RELATED_OPERATIONS)
    }

    /// Returns `true` if the signed flag is set.
    #[inline]
    pub fn is_signed(&self) -> bool {
        self.contains(Self::SIGNED)
    }

    /// Set the response flag.
    #[inline]
    pub fn set_response(&mut self) {
        self.set(Self::SERVER_TO_REDIR);
    }

    /// Set the async flag.
    #[inline]
    pub fn set_async(&mut self) {
        self.set(Self::ASYNC_COMMAND);
    }

    /// Set the related-operations flag.
    #[inline]
    pub fn set_related(&mut self) {
        self.set(Self::RELATED_OPERATIONS);
    }

    /// Set the signed flag.
    #[inline]
    pub fn set_signed(&mut self) {
        self.set(Self::SIGNED);
    }
}

impl_flags!(HeaderFlags, u32);

// ── SecurityMode ────────────────────────────────────────────────────────

/// Security mode flags (16-bit field from MS-SMB2 2.2.3/2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityMode(pub u16);

impl SecurityMode {
    /// Signing is supported (enabled).
    pub const SIGNING_ENABLED: u16 = 0x0001;
    /// Signing is required.
    pub const SIGNING_REQUIRED: u16 = 0x0002;

    /// Returns `true` if signing is enabled.
    #[inline]
    pub fn signing_enabled(&self) -> bool {
        self.contains(Self::SIGNING_ENABLED)
    }

    /// Returns `true` if signing is required.
    #[inline]
    pub fn signing_required(&self) -> bool {
        self.contains(Self::SIGNING_REQUIRED)
    }
}

impl_flags!(SecurityMode, u16);

// ── Capabilities ────────────────────────────────────────────────────────

/// Server/client capability flags (32-bit field from MS-SMB2 2.2.3/2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Distributed File System (DFS) support.
    pub const DFS: u32 = 0x0000_0001;
    /// Leasing support.
    pub const LEASING: u32 = 0x0000_0002;
    /// Multi-credit (large MTU) support.
    pub const LARGE_MTU: u32 = 0x0000_0004;
    /// Multi-channel support.
    pub const MULTI_CHANNEL: u32 = 0x0000_0008;
    /// Persistent handle support.
    pub const PERSISTENT_HANDLES: u32 = 0x0000_0010;
    /// Directory leasing support.
    pub const DIRECTORY_LEASING: u32 = 0x0000_0020;
    /// Encryption support.
    pub const ENCRYPTION: u32 = 0x0000_0040;
}

impl_flags!(Capabilities, u32);

// ── ShareFlags ──────────────────────────────────────────────────────────

/// Share property flags (32-bit field from MS-SMB2 2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareFlags(pub u32);

impl ShareFlags {
    /// The share is in a DFS tree structure.
    pub const DFS: u32 = 0x0000_0001;
    /// The share is a DFS root.
    pub const DFS_ROOT: u32 = 0x0000_0002;

    // Offline caching policies (mutually exclusive, stored in bits 4-5).

    /// The client can cache files explicitly selected by the user.
    pub const MANUAL_CACHING: u32 = 0x0000_0000;
    /// The client can automatically cache files used by the user.
    pub const AUTO_CACHING: u32 = 0x0000_0010;
    /// Auto-cache with offline mode even when the share is available.
    pub const VDO_CACHING: u32 = 0x0000_0020;
    /// Offline caching must not occur.
    pub const NO_CACHING: u32 = 0x0000_0030;

    /// Disallows exclusive file opens that deny reads.
    pub const RESTRICT_EXCLUSIVE_OPENS: u32 = 0x0000_0100;
    /// Disallows exclusive opens that prevent deletion.
    pub const FORCE_SHARED_DELETE: u32 = 0x0000_0200;
    /// Allow namespace caching (client must ignore).
    pub const ALLOW_NAMESPACE_CACHING: u32 = 0x0000_0400;
    /// Server filters directory entries based on access permissions.
    pub const ACCESS_BASED_DIRECTORY_ENUM: u32 = 0x0000_0800;
    /// Server will not issue exclusive caching rights.
    pub const FORCE_LEVELII_OPLOCK: u32 = 0x0000_1000;
    /// Hash generation v1 for branch cache (not valid for SMB 2.0.2).
    pub const ENABLE_HASH_V1: u32 = 0x0000_2000;
    /// Hash generation v2 for branch cache.
    pub const ENABLE_HASH_V2: u32 = 0x0000_4000;
    /// Encryption of remote file access messages required (SMB 3.x).
    pub const ENCRYPT_DATA: u32 = 0x0000_8000;
    /// The share supports identity remoting.
    pub const IDENTITY_REMOTING: u32 = 0x0004_0000;
    /// The server supports compression on this share (SMB 3.1.1).
    pub const COMPRESS_DATA: u32 = 0x0010_0000;
    /// Prefer isolated transport for this share (advisory).
    pub const ISOLATED_TRANSPORT: u32 = 0x0020_0000;
}

impl_flags!(ShareFlags, u32);

// ── ShareCapabilities ───────────────────────────────────────────────────

/// Share capability flags (32-bit field from MS-SMB2 2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShareCapabilities(pub u32);

impl ShareCapabilities {
    /// The share is part of a DFS tree.
    pub const DFS: u32 = 0x0000_0008;
    /// The share has continuously available file handles.
    pub const CONTINUOUS_AVAILABILITY: u32 = 0x0000_0010;
    /// The share is a scale-out share.
    pub const SCALEOUT: u32 = 0x0000_0020;
    /// The share is a cluster share.
    pub const CLUSTER: u32 = 0x0000_0040;
    /// The share is an asymmetric share.
    pub const ASYMMETRIC: u32 = 0x0000_0080;
    /// The share supports redirect to owner.
    pub const REDIRECT_TO_OWNER: u32 = 0x0000_0100;
}

impl_flags!(ShareCapabilities, u32);

// ── FileAccessMask ──────────────────────────────────────────────────────

/// File access rights mask (32-bit, from MS-SMB2 2.2.13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAccessMask(pub u32);

impl FileAccessMask {
    /// Read data from the file.
    pub const FILE_READ_DATA: u32 = 0x0000_0001;
    /// Write data to the file.
    pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
    /// Append data to the file.
    pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
    /// Read extended attributes.
    pub const FILE_READ_EA: u32 = 0x0000_0008;
    /// Write extended attributes.
    pub const FILE_WRITE_EA: u32 = 0x0000_0010;
    /// Execute the file.
    pub const FILE_EXECUTE: u32 = 0x0000_0020;
    /// Read file attributes.
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    /// Write file attributes.
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    /// Delete the object.
    pub const DELETE: u32 = 0x0001_0000;
    /// Read the security descriptor.
    pub const READ_CONTROL: u32 = 0x0002_0000;
    /// Modify the DACL.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// Change the owner.
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// Synchronize access.
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    /// Request maximum allowed access.
    pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    /// All possible access rights.
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// Execute access.
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    /// Write access.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// Read access.
    pub const GENERIC_READ: u32 = 0x8000_0000;
}

impl_flags!(FileAccessMask, u32);

#[cfg(test)]
mod tests {
    use super::*;

    // ── HeaderFlags ─────────────────────────────────────────────────

    #[test]
    fn header_flags_default_is_zero() {
        let f = HeaderFlags::default();
        assert_eq!(f.bits(), 0);
        assert!(!f.is_response());
        assert!(!f.is_async());
        assert!(!f.is_related());
        assert!(!f.is_signed());
    }

    #[test]
    fn header_flags_set_and_check() {
        let mut f = HeaderFlags::default();
        f.set_response();
        assert!(f.is_response());
        assert!(!f.is_async());

        f.set_signed();
        assert!(f.is_signed());
        assert!(f.is_response());
    }

    #[test]
    fn header_flags_clear() {
        let mut f = HeaderFlags::new(0xFFFF_FFFF);
        assert!(f.is_response());
        f.clear(HeaderFlags::SERVER_TO_REDIR);
        assert!(!f.is_response());
        assert!(f.is_async()); // other flags untouched
    }

    #[test]
    fn header_flags_contains() {
        let f = HeaderFlags::new(HeaderFlags::SIGNED | HeaderFlags::ASYNC_COMMAND);
        assert!(f.contains(HeaderFlags::SIGNED));
        assert!(f.contains(HeaderFlags::ASYNC_COMMAND));
        assert!(!f.contains(HeaderFlags::SERVER_TO_REDIR));
    }

    #[test]
    fn header_flags_bitor() {
        let a = HeaderFlags::new(HeaderFlags::SERVER_TO_REDIR);
        let b = HeaderFlags::new(HeaderFlags::SIGNED);
        let c = a | b;
        assert!(c.is_response());
        assert!(c.is_signed());
    }

    #[test]
    fn header_flags_bitand() {
        let a = HeaderFlags::new(HeaderFlags::SERVER_TO_REDIR | HeaderFlags::SIGNED);
        let b = HeaderFlags::new(HeaderFlags::SIGNED);
        let c = a & b;
        assert!(!c.is_response());
        assert!(c.is_signed());
    }

    #[test]
    fn header_flags_bitor_assign() {
        let mut a = HeaderFlags::new(HeaderFlags::SERVER_TO_REDIR);
        a |= HeaderFlags::new(HeaderFlags::ASYNC_COMMAND);
        assert!(a.is_response());
        assert!(a.is_async());
    }

    // ── SecurityMode ────────────────────────────────────────────────

    #[test]
    fn security_mode_signing_enabled() {
        let m = SecurityMode::new(SecurityMode::SIGNING_ENABLED);
        assert!(m.signing_enabled());
        assert!(!m.signing_required());
    }

    #[test]
    fn security_mode_signing_required() {
        let m = SecurityMode::new(SecurityMode::SIGNING_ENABLED | SecurityMode::SIGNING_REQUIRED);
        assert!(m.signing_enabled());
        assert!(m.signing_required());
    }

    // ── Capabilities ────────────────────────────────────────────────

    #[test]
    fn capabilities_combine_with_bitor() {
        let a = Capabilities::new(Capabilities::DFS);
        let b = Capabilities::new(Capabilities::ENCRYPTION);
        let c = a | b;
        assert!(c.contains(Capabilities::DFS));
        assert!(c.contains(Capabilities::ENCRYPTION));
        assert!(!c.contains(Capabilities::LEASING));
    }

    #[test]
    fn capabilities_set_and_clear() {
        let mut c = Capabilities::default();
        c.set(Capabilities::LARGE_MTU);
        assert!(c.contains(Capabilities::LARGE_MTU));
        c.clear(Capabilities::LARGE_MTU);
        assert!(!c.contains(Capabilities::LARGE_MTU));
    }

    // ── ShareFlags ──────────────────────────────────────────────────

    #[test]
    fn share_flags_encrypt_data() {
        let f = ShareFlags::new(ShareFlags::ENCRYPT_DATA | ShareFlags::DFS);
        assert!(f.contains(ShareFlags::ENCRYPT_DATA));
        assert!(f.contains(ShareFlags::DFS));
        assert!(!f.contains(ShareFlags::COMPRESS_DATA));
    }

    // ── ShareCapabilities ───────────────────────────────────────────

    #[test]
    fn share_capabilities_dfs() {
        let c = ShareCapabilities::new(ShareCapabilities::DFS);
        assert!(c.contains(ShareCapabilities::DFS));
        assert!(!c.contains(ShareCapabilities::CLUSTER));
    }

    // ── FileAccessMask ──────────────────────────────────────────────

    #[test]
    fn file_access_mask_generic_read() {
        let m = FileAccessMask::new(FileAccessMask::GENERIC_READ);
        assert!(m.contains(FileAccessMask::GENERIC_READ));
        assert!(!m.contains(FileAccessMask::GENERIC_WRITE));
    }

    #[test]
    fn file_access_mask_combine() {
        let m =
            FileAccessMask::new(FileAccessMask::FILE_READ_DATA | FileAccessMask::FILE_WRITE_DATA);
        assert!(m.contains(FileAccessMask::FILE_READ_DATA));
        assert!(m.contains(FileAccessMask::FILE_WRITE_DATA));
        assert!(!m.contains(FileAccessMask::DELETE));
    }
}
