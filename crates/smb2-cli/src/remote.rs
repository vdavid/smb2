//! Asking the server what's already at a path.
//!
//! Both `put` and `mkdir` have to know whether a name is taken by a file or by
//! a directory before they decide what to do, and both of them get it wrong in
//! a destructive or misleading way if they guess.

use anyhow::Result;
use smb2::types::status::NtStatus;
use smb2::{SmbClient, Tree};

/// What's sitting at a path on the share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKind {
    Missing,
    File,
    Directory,
}

/// What the server has at `path`. Only a clean "it isn't there" counts as
/// missing: any other error comes back as an error, because a caller that
/// treats `ACCESS_DENIED` as "nothing there" goes on to clobber a directory or
/// to report a success that never happened.
pub async fn kind(client: &mut SmbClient, tree: &mut Tree, path: &str) -> Result<RemoteKind> {
    // The share root is a directory, and asking about the empty path isn't
    // something the server will answer.
    if path.is_empty() {
        return Ok(RemoteKind::Directory);
    }
    match client.stat(tree, path).await {
        Ok(info) if info.is_directory => Ok(RemoteKind::Directory),
        Ok(_) => Ok(RemoteKind::File),
        Err(error) if is_not_found(&error) => Ok(RemoteKind::Missing),
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

fn is_not_found(error: &smb2::Error) -> bool {
    matches!(
        error.status(),
        Some(NtStatus::OBJECT_NAME_NOT_FOUND)
            | Some(NtStatus::OBJECT_PATH_NOT_FOUND)
            | Some(NtStatus::NO_SUCH_FILE)
    )
}
