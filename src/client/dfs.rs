//! DFS referral IOCTL helper.
//!
//! Sends `FSCTL_DFS_GET_REFERRALS` via IOCTL to resolve DFS paths. Connects
//! to IPC$ for the IOCTL exchange, similar to how `shares.rs` does for RPC.

// Not yet called from non-test code (wired in a later step).
#![allow(dead_code)]

use log::debug;

use crate::client::connection::Connection;
use crate::error::Result;
use crate::msg::dfs::{ReqGetDfsReferral, RespGetDfsReferral};
use crate::msg::ioctl::{
    IoctlRequest, IoctlResponse, FSCTL_DFS_GET_REFERRALS, SMB2_0_IOCTL_IS_FSCTL,
};
use crate::msg::tree_connect::{TreeConnectRequest, TreeConnectRequestFlags, TreeConnectResponse};
use crate::msg::tree_disconnect::TreeDisconnectRequest;
use crate::pack::{Pack, ReadCursor, Unpack, WriteCursor};
use crate::types::status::NtStatus;
use crate::types::{Command, FileId, TreeId};
use crate::Error;

/// Maximum output buffer size for DFS referral responses (8 KiB).
const DFS_MAX_OUTPUT_RESPONSE: u32 = 8192;

/// Send a DFS referral request and return the parsed response.
///
/// Connects to IPC$ (or reuses an existing tree), sends
/// `FSCTL_DFS_GET_REFERRALS` via IOCTL with `FileId::SENTINEL`, and
/// parses the response.
///
/// The `path` should be a UNC-style path with a single leading backslash
/// (for example, `\server\share\dir`).
pub(crate) async fn get_dfs_referral(
    conn: &mut Connection,
    path: &str,
) -> Result<RespGetDfsReferral> {
    // 1. Tree-connect to IPC$
    let tree_id = tree_connect_ipc(conn).await?;

    // Send the IOCTL, then clean up regardless of outcome
    let result = send_dfs_ioctl(conn, tree_id, path).await;

    // Tree-disconnect IPC$ (best-effort -- don't mask the real error)
    let _ = tree_disconnect(conn, tree_id).await;

    result
}

/// Connect to the IPC$ share, returning the tree ID.
async fn tree_connect_ipc(conn: &mut Connection) -> Result<TreeId> {
    let server = conn.server_name().to_string();
    let unc_path = format!(r"\\{}\IPC$", server);

    let req = TreeConnectRequest {
        flags: TreeConnectRequestFlags::default(),
        path: unc_path,
    };

    let (_, _) = conn.send_request(Command::TreeConnect, &req, None).await?;
    let (resp_header, resp_body, _) = conn.receive_response().await?;

    if resp_header.command != Command::TreeConnect {
        return Err(Error::invalid_data(format!(
            "expected TreeConnect response, got {:?}",
            resp_header.command
        )));
    }

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::TreeConnect,
        });
    }

    let mut cursor = ReadCursor::new(&resp_body);
    let _resp = TreeConnectResponse::unpack(&mut cursor)?;

    let tree_id = resp_header
        .tree_id
        .ok_or_else(|| Error::invalid_data("TreeConnect response missing tree ID"))?;

    debug!("dfs: connected to IPC$, tree_id={}", tree_id);
    Ok(tree_id)
}

/// Build and send the FSCTL_DFS_GET_REFERRALS IOCTL, parse the response.
async fn send_dfs_ioctl(
    conn: &mut Connection,
    tree_id: TreeId,
    path: &str,
) -> Result<RespGetDfsReferral> {
    // Build the referral request payload
    let referral_req = ReqGetDfsReferral {
        max_referral_level: 4,
        request_file_name: path.to_string(),
    };
    let mut req_cursor = WriteCursor::new();
    referral_req.pack(&mut req_cursor);
    let input_data = req_cursor.into_inner();

    debug!(
        "dfs: sending FSCTL_DFS_GET_REFERRALS for {:?} ({} bytes input)",
        path,
        input_data.len()
    );

    // Build the IOCTL request
    let ioctl_req = IoctlRequest {
        ctl_code: FSCTL_DFS_GET_REFERRALS,
        file_id: FileId::SENTINEL,
        max_input_response: 0,
        max_output_response: DFS_MAX_OUTPUT_RESPONSE,
        flags: SMB2_0_IOCTL_IS_FSCTL,
        input_data,
    };

    let (_, _) = conn
        .send_request(Command::Ioctl, &ioctl_req, Some(tree_id))
        .await?;
    let (resp_header, resp_body, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::Ioctl,
        });
    }

    // Parse the IOCTL response envelope
    let mut cursor = ReadCursor::new(&resp_body);
    let ioctl_resp = IoctlResponse::unpack(&mut cursor)?;

    debug!(
        "dfs: received IOCTL response ({} bytes output)",
        ioctl_resp.output_data.len()
    );

    // Parse the DFS referral from the output buffer
    let mut ref_cursor = ReadCursor::new(&ioctl_resp.output_data);
    let referral_resp = RespGetDfsReferral::unpack(&mut ref_cursor)?;

    debug!(
        "dfs: parsed {} referral entries (path_consumed={})",
        referral_resp.entries.len(),
        referral_resp.path_consumed
    );

    Ok(referral_resp)
}

/// Disconnect from a tree.
async fn tree_disconnect(conn: &mut Connection, tree_id: TreeId) -> Result<()> {
    let body = TreeDisconnectRequest;
    let (_, _) = conn
        .send_request(Command::TreeDisconnect, &body, Some(tree_id))
        .await?;
    let (resp_header, _, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::TreeDisconnect,
        });
    }

    debug!("dfs: disconnected from IPC$");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::client::test_helpers::{build_tree_connect_response, setup_connection};
    use crate::msg::header::{ErrorResponse, Header};
    use crate::msg::ioctl::IoctlResponse as IoctlResp;
    use crate::msg::tree_connect::ShareType;
    use crate::msg::tree_disconnect::TreeDisconnectResponse;
    use crate::transport::MockTransport;
    use crate::types::TreeId;
    use std::sync::Arc;

    /// Build an IOCTL response containing the given output data.
    fn build_ioctl_response(output_data: Vec<u8>) -> Vec<u8> {
        let mut h = Header::new_request(Command::Ioctl);
        h.flags.set_response();
        h.credits = 32;

        let body = IoctlResp {
            ctl_code: FSCTL_DFS_GET_REFERRALS,
            file_id: FileId::SENTINEL,
            flags: SMB2_0_IOCTL_IS_FSCTL,
            output_data,
        };

        pack_message(&h, &body)
    }

    /// Build an IOCTL error response with the given status.
    fn build_ioctl_error_response(status: NtStatus) -> Vec<u8> {
        let mut h = Header::new_request(Command::Ioctl);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;

        let body = ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        };

        pack_message(&h, &body)
    }

    /// Build a TREE_DISCONNECT response.
    fn build_tree_disconnect_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeDisconnect);
        h.flags.set_response();
        h.credits = 32;
        pack_message(&h, &TreeDisconnectResponse)
    }

    /// Pack a known DFS referral response into bytes.
    ///
    /// Builds a V3 referral with the given entries.
    fn pack_dfs_referral_response(
        path_consumed: u16,
        header_flags: u32,
        entries: &[(&str, &str, &str, u32)], // (dfs_path, alt_path, net_addr, ttl)
    ) -> Vec<u8> {
        // We build a V3 referral response manually.
        // Entry fixed size: 4 (version+size) + 2+2+4 (server_type+flags+ttl)
        //   + 2+2+2 (offsets) + 16 (guid) = 34 bytes
        let entry_fixed_size: u16 = 34;
        let num_entries = entries.len() as u16;
        let total_fixed = entry_fixed_size * num_entries;

        // Pre-compute all string bytes
        let entry_strings: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = entries
            .iter()
            .map(|(dfs, alt, net, _)| {
                (
                    encode_null_utf16(dfs),
                    encode_null_utf16(alt),
                    encode_null_utf16(net),
                )
            })
            .collect();

        // Compute cumulative string offsets relative to each entry's start.
        // All strings come after all fixed entries. The offset for entry i
        // is relative to entry i's start position.
        let mut buf = Vec::new();

        // Response header (8 bytes)
        buf.extend_from_slice(&path_consumed.to_le_bytes());
        buf.extend_from_slice(&num_entries.to_le_bytes());
        buf.extend_from_slice(&header_flags.to_le_bytes());

        // Calculate where strings start (after all fixed entries, but
        // offsets are measured from the start of the entry data, not from
        // the response header -- since RespGetDfsReferral::unpack reads
        // the header first and then works with the remaining bytes).
        //
        // Actually, offsets in V3 entries are relative to the entry start
        // within the entry data buffer.

        // Accumulate string buffer contents and compute per-entry offsets.
        let mut string_buf = Vec::new();
        let mut per_entry_offsets = Vec::new();

        for (i, (dfs_bytes, alt_bytes, net_bytes)) in entry_strings.iter().enumerate() {
            let entry_start = i as u16 * entry_fixed_size;
            let strings_base = total_fixed + string_buf.len() as u16;

            let dfs_offset = strings_base - entry_start;
            let alt_offset = dfs_offset + dfs_bytes.len() as u16;
            let net_offset = alt_offset + alt_bytes.len() as u16;

            per_entry_offsets.push((dfs_offset, alt_offset, net_offset));

            string_buf.extend_from_slice(dfs_bytes);
            string_buf.extend_from_slice(alt_bytes);
            string_buf.extend_from_slice(net_bytes);
        }

        // Write fixed entries
        for (i, (_, _, _, ttl)) in entries.iter().enumerate() {
            let (dfs_off, alt_off, net_off) = per_entry_offsets[i];

            buf.extend_from_slice(&3u16.to_le_bytes()); // version = 3
            buf.extend_from_slice(&entry_fixed_size.to_le_bytes()); // size
            buf.extend_from_slice(&0u16.to_le_bytes()); // server_type
            buf.extend_from_slice(&0u16.to_le_bytes()); // referral_entry_flags
            buf.extend_from_slice(&ttl.to_le_bytes()); // ttl
            buf.extend_from_slice(&dfs_off.to_le_bytes());
            buf.extend_from_slice(&alt_off.to_le_bytes());
            buf.extend_from_slice(&net_off.to_le_bytes());
            buf.extend_from_slice(&[0u8; 16]); // service_site_guid
        }

        // Write string buffer
        buf.extend_from_slice(&string_buf);

        buf
    }

    /// Encode a string as null-terminated UTF-16LE bytes.
    fn encode_null_utf16(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for cu in s.encode_utf16() {
            out.extend_from_slice(&cu.to_le_bytes());
        }
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    #[tokio::test]
    async fn dfs_referral_ioctl_flow() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        let tree_id = TreeId(99);

        // Build the DFS referral payload
        let referral_bytes = pack_dfs_referral_response(
            48,   // path_consumed
            0x02, // header_flags (StorageServers)
            &[
                (
                    r"\domain\dfs\docs",
                    r"\domain\dfs\docs",
                    r"\server1\share",
                    600,
                ),
                (
                    r"\domain\dfs\docs",
                    r"\domain\dfs\docs",
                    r"\server2\share",
                    300,
                ),
            ],
        );

        // Queue responses: TreeConnect, IOCTL, TreeDisconnect
        mock.queue_response(build_tree_connect_response(tree_id, ShareType::Pipe));
        mock.queue_response(build_ioctl_response(referral_bytes));
        mock.queue_response(build_tree_disconnect_response());

        let resp = get_dfs_referral(&mut conn, r"\domain\dfs\docs")
            .await
            .unwrap();

        assert_eq!(resp.path_consumed, 48);
        assert_eq!(resp.header_flags, 0x02);
        assert_eq!(resp.entries.len(), 2);

        assert_eq!(resp.entries[0].version, 3);
        assert_eq!(resp.entries[0].dfs_path, r"\domain\dfs\docs");
        assert_eq!(resp.entries[0].network_address, r"\server1\share");
        assert_eq!(resp.entries[0].ttl, 600);

        assert_eq!(resp.entries[1].network_address, r"\server2\share");
        assert_eq!(resp.entries[1].ttl, 300);

        // Should have sent 3 messages: TreeConnect, IOCTL, TreeDisconnect
        assert_eq!(mock.sent_count(), 3);
    }

    #[tokio::test]
    async fn dfs_referral_ioctl_error() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        let tree_id = TreeId(99);

        // Queue responses: TreeConnect, IOCTL error, TreeDisconnect
        mock.queue_response(build_tree_connect_response(tree_id, ShareType::Pipe));
        mock.queue_response(build_ioctl_error_response(NtStatus::NOT_FOUND));
        mock.queue_response(build_tree_disconnect_response());

        let result = get_dfs_referral(&mut conn, r"\nonexistent\path").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            Error::Protocol { status, command } => {
                assert_eq!(*status, NtStatus::NOT_FOUND);
                assert_eq!(*command, Command::Ioctl);
            }
            other => panic!("expected Protocol error, got: {other:?}"),
        }

        // Should still send TreeDisconnect even after IOCTL error
        assert_eq!(mock.sent_count(), 3);
    }
}
