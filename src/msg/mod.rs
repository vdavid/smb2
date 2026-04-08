//! Wire format message structs for SMB2/3.
//!
//! Each sub-module corresponds to one SMB2 command type with its
//! request and response structures.
//!
//! Most users don't need this module directly -- use [`SmbClient`](crate::SmbClient)
//! for high-level file operations.

/// Generates a trivial 4-byte SMB2 stub message (StructureSize + Reserved).
///
/// Many SMB2 commands (echo, cancel, logoff, tree_disconnect) have request
/// and/or response structs that are identical: 2-byte StructureSize (always 4)
/// plus 2-byte Reserved. This macro generates the struct definition and its
/// `Pack`/`Unpack` impls from a single declaration.
///
/// # Usage
///
/// ```ignore
/// trivial_message! {
///     /// Doc comment for the struct.
///     pub struct EchoRequest;
/// }
/// ```
macro_rules! trivial_message {
    (
        $(#[$meta:meta])*
        pub struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            /// The structure size field is always 4.
            pub const STRUCTURE_SIZE: u16 = 4;
        }

        impl crate::pack::Pack for $name {
            fn pack(&self, cursor: &mut crate::pack::WriteCursor) {
                // StructureSize (2 bytes)
                cursor.write_u16_le(Self::STRUCTURE_SIZE);
                // Reserved (2 bytes)
                cursor.write_u16_le(0);
            }
        }

        impl crate::pack::Unpack for $name {
            fn unpack(cursor: &mut crate::pack::ReadCursor<'_>) -> crate::error::Result<Self> {
                // StructureSize (2 bytes)
                let structure_size = cursor.read_u16_le()?;
                if structure_size != Self::STRUCTURE_SIZE {
                    return Err(crate::Error::invalid_data(format!(
                        "invalid {} structure size: expected {}, got {}",
                        stringify!($name),
                        Self::STRUCTURE_SIZE,
                        structure_size
                    )));
                }

                // Reserved (2 bytes)
                let _reserved = cursor.read_u16_le()?;

                Ok($name)
            }
        }
    };
}

pub(crate) use trivial_message;

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
