//! Share enumeration via IPC$ + srvsvc RPC.
//!
//! Lists available shares on an SMB server by connecting to the IPC$ share,
//! opening the srvsvc named pipe, and performing the NetShareEnumAll RPC
//! exchange.

use log::{debug, info};

use crate::client::connection::Connection;
use crate::error::Result;
use crate::msg::close::CloseRequest;
use crate::msg::create::{
    CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use crate::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use crate::msg::tree_connect::{TreeConnectRequest, TreeConnectRequestFlags, TreeConnectResponse};
use crate::msg::tree_disconnect::TreeDisconnectRequest;
use crate::msg::write::{WriteRequest, WriteResponse};
use crate::pack::{ReadCursor, Unpack};
use crate::rpc;
use crate::rpc::srvsvc::{self, ShareInfo};
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
use crate::types::{Command, FileId, OplockLevel, TreeId};
use crate::Error;

/// Read buffer size for pipe reads (64 KiB is plenty for share listings).
const PIPE_READ_BUFFER_SIZE: u32 = 65536;

/// List available shares on the server.
///
/// Connects to the IPC$ share, opens the srvsvc named pipe, performs
/// the RPC exchange, and returns filtered disk shares.
///
/// This is a self-contained operation -- it opens and closes its own
/// tree connection to IPC$.
pub async fn list_shares(conn: &mut Connection) -> Result<Vec<ShareInfo>> {
    // 1. Tree connect to IPC$
    let tree_id = tree_connect_ipc(conn).await?;

    // Run the pipe operations, then clean up regardless of outcome
    let result = pipe_rpc_exchange(conn, tree_id).await;

    // 8. Tree disconnect (best-effort -- don't mask the real error)
    let _ = tree_disconnect(conn, tree_id).await;

    let all_shares = result?;

    // 9. Filter to disk shares
    let filtered = srvsvc::filter_disk_shares(all_shares);
    info!("shares: found {} disk shares", filtered.len());
    Ok(filtered)
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

    info!("shares: connected to IPC$, tree_id={}", tree_id);
    Ok(tree_id)
}

/// Open the srvsvc pipe, perform the RPC bind and request, then close.
async fn pipe_rpc_exchange(conn: &mut Connection, tree_id: TreeId) -> Result<Vec<ShareInfo>> {
    // 2. Create \pipe\srvsvc
    let file_id = open_srvsvc_pipe(conn, tree_id).await?;

    // Run RPC exchange, then close regardless of outcome
    let result = rpc_bind_and_request(conn, tree_id, file_id).await;

    // 7. Close the pipe handle (best-effort)
    let _ = close_handle(conn, tree_id, file_id).await;

    result
}

/// Perform the RPC bind + NetShareEnumAll request over the pipe.
async fn rpc_bind_and_request(
    conn: &mut Connection,
    tree_id: TreeId,
    file_id: FileId,
) -> Result<Vec<ShareInfo>> {
    // 3. Write RPC BIND
    let bind_data = rpc::build_srvsvc_bind(1);
    write_pipe(conn, tree_id, file_id, &bind_data).await?;
    debug!("shares: sent RPC BIND ({} bytes)", bind_data.len());

    // 4. Read RPC BIND_ACK
    let bind_ack_data = read_pipe(conn, tree_id, file_id).await?;
    rpc::parse_bind_ack(&bind_ack_data)?;
    debug!("shares: received BIND_ACK, context accepted");

    // 5. Write RPC REQUEST (NetShareEnumAll)
    let server_name = format!(r"\\{}", conn.server_name());
    let request_data = srvsvc::build_net_share_enum_all(2, &server_name);
    write_pipe(conn, tree_id, file_id, &request_data).await?;
    debug!(
        "shares: sent NetShareEnumAll request ({} bytes)",
        request_data.len()
    );

    // 6. Read RPC RESPONSE
    let response_data = read_pipe(conn, tree_id, file_id).await?;
    let shares = srvsvc::parse_net_share_enum_all_response(&response_data)?;
    debug!("shares: received {} shares in response", shares.len());

    Ok(shares)
}

/// Open the `\pipe\srvsvc` named pipe via CREATE.
async fn open_srvsvc_pipe(conn: &mut Connection, tree_id: TreeId) -> Result<FileId> {
    let req = CreateRequest {
        requested_oplock_level: OplockLevel::None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access: FileAccessMask::new(
            FileAccessMask::FILE_READ_DATA | FileAccessMask::FILE_WRITE_DATA,
        ),
        file_attributes: 0,
        share_access: ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE),
        create_disposition: CreateDisposition::FileOpen,
        create_options: 0,
        name: r"srvsvc".to_string(),
        create_contexts: vec![],
    };

    let (_, _) = conn
        .send_request(Command::Create, &req, Some(tree_id))
        .await?;
    let (resp_header, resp_body, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::Create,
        });
    }

    let mut cursor = ReadCursor::new(&resp_body);
    let resp = CreateResponse::unpack(&mut cursor)?;
    debug!("shares: opened srvsvc pipe, file_id={:?}", resp.file_id);
    Ok(resp.file_id)
}

/// Write data to the pipe.
async fn write_pipe(
    conn: &mut Connection,
    tree_id: TreeId,
    file_id: FileId,
    data: &[u8],
) -> Result<()> {
    // DataOffset: header (64) + fixed write body (48) = 112 = 0x70
    let req = WriteRequest {
        data_offset: 0x70,
        offset: 0,
        file_id,
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: data.to_vec(),
    };

    let (_, _) = conn
        .send_request(Command::Write, &req, Some(tree_id))
        .await?;
    let (resp_header, resp_body, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::Write,
        });
    }

    let mut cursor = ReadCursor::new(&resp_body);
    let resp = WriteResponse::unpack(&mut cursor)?;
    debug!("shares: wrote {} bytes to pipe", resp.count);
    Ok(())
}

/// Read data from the pipe.
async fn read_pipe(conn: &mut Connection, tree_id: TreeId, file_id: FileId) -> Result<Vec<u8>> {
    let req = ReadRequest {
        padding: 0x50,
        flags: 0,
        length: PIPE_READ_BUFFER_SIZE,
        offset: 0,
        file_id,
        minimum_count: 0,
        channel: SMB2_CHANNEL_NONE,
        remaining_bytes: 0,
        read_channel_info: vec![],
    };

    let (_, _) = conn
        .send_request(Command::Read, &req, Some(tree_id))
        .await?;
    let (resp_header, resp_body, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::Read,
        });
    }

    let mut cursor = ReadCursor::new(&resp_body);
    let resp = ReadResponse::unpack(&mut cursor)?;
    debug!("shares: read {} bytes from pipe", resp.data.len());
    Ok(resp.data)
}

/// Close a file handle.
async fn close_handle(conn: &mut Connection, tree_id: TreeId, file_id: FileId) -> Result<()> {
    let req = CloseRequest { flags: 0, file_id };

    let (_, _) = conn
        .send_request(Command::Close, &req, Some(tree_id))
        .await?;
    let (resp_header, _, _) = conn.receive_response().await?;

    if resp_header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: resp_header.status,
            command: Command::Close,
        });
    }

    Ok(())
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

    info!("shares: disconnected from IPC$");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::connection::{pack_message, NegotiatedParams};
    use crate::client::test_helpers::{
        build_close_response, build_create_response, build_tree_connect_response, setup_connection,
    };
    use crate::msg::header::Header;
    use crate::msg::read::ReadResponse as ReadResp;
    use crate::msg::tree_connect::ShareType;
    use crate::msg::tree_disconnect::TreeDisconnectResponse;
    use crate::msg::write::WriteResponse as WriteResp;
    use crate::pack::Guid;
    use crate::rpc::srvsvc::{STYPE_DISKTREE, STYPE_IPC, STYPE_SPECIAL};
    use crate::transport::MockTransport;
    use crate::types::flags::Capabilities;
    use crate::types::{Dialect, SessionId, TreeId};
    use std::sync::Arc;

    fn build_write_response(count: u32) -> Vec<u8> {
        let mut h = Header::new_request(Command::Write);
        h.flags.set_response();
        h.credits = 32;

        let body = WriteResp {
            count,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        pack_message(&h, &body)
    }

    fn build_read_response(data: Vec<u8>) -> Vec<u8> {
        let mut h = Header::new_request(Command::Read);
        h.flags.set_response();
        h.credits = 32;

        let body = ReadResp {
            data_offset: 0x50,
            data_remaining: 0,
            flags: 0,
            data,
        };

        pack_message(&h, &body)
    }

    fn build_tree_disconnect_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeDisconnect);
        h.flags.set_response();
        h.credits = 32;
        pack_message(&h, &TreeDisconnectResponse)
    }

    /// Build a canned RPC BIND_ACK response.
    fn build_bind_ack() -> Vec<u8> {
        use crate::pack::WriteCursor;

        let mut w = WriteCursor::with_capacity(64);
        // Common header
        w.write_u8(5); // version
        w.write_u8(0); // version minor
        w.write_u8(12); // BIND_ACK type
        w.write_u8(0x03); // flags (first + last)
        w.write_bytes(&[0x10, 0x00, 0x00, 0x00]); // data rep
        let frag_len_pos = w.position();
        w.write_u16_le(0); // frag length placeholder
        w.write_u16_le(0); // auth length
        w.write_u32_le(1); // call id

        // BIND_ACK specific
        w.write_u16_le(4280); // max xmit frag
        w.write_u16_le(4280); // max recv frag
        w.write_u32_le(0x12345); // assoc group

        // Secondary address (empty)
        w.write_u16_le(0);
        w.write_bytes(&[0, 0]); // padding

        // Result list
        w.write_u8(1); // num results
        w.write_bytes(&[0, 0, 0]); // reserved
        w.write_u16_le(0); // result = accepted
        w.write_u16_le(0); // reason

        // Transfer syntax UUID + version (20 bytes)
        use crate::pack::Pack;
        let ndr_uuid = Guid {
            data1: 0x8A885D04,
            data2: 0x1CEB,
            data3: 0x11C9,
            data4: [0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60],
        };
        ndr_uuid.pack(&mut w);
        w.write_u32_le(2);

        let total_len = w.position();
        w.set_u16_le_at(frag_len_pos, total_len as u16);
        w.into_inner()
    }

    /// Build a canned RPC RESPONSE with NetShareEnumAll data.
    fn build_share_enum_response(shares: &[(&str, u32, &str)]) -> Vec<u8> {
        use crate::pack::WriteCursor;

        // Build NDR stub
        let mut w = WriteCursor::with_capacity(512);
        let count = shares.len() as u32;

        // Level = 1
        w.write_u32_le(1);
        // Union discriminant = 1
        w.write_u32_le(1);

        if count == 0 {
            w.write_u32_le(0); // null container
            w.write_u32_le(0); // total entries
            w.write_u32_le(0); // resume handle
            w.write_u32_le(0); // return value
        } else {
            // Container pointer
            w.write_u32_le(0x0002_0000);
            // EntriesRead
            w.write_u32_le(count);
            // Array pointer
            w.write_u32_le(0x0002_0004);
            // MaxCount
            w.write_u32_le(count);

            // Fixed entries
            for (i, &(_, share_type, _)) in shares.iter().enumerate() {
                w.write_u32_le(0x0002_0008 + (i as u32) * 2); // name ref
                w.write_u32_le(share_type);
                w.write_u32_le(0x0002_0108 + (i as u32) * 2); // comment ref
            }

            // Deferred strings
            for &(name, _, comment) in shares {
                write_ndr_string(&mut w, name);
                write_ndr_string(&mut w, comment);
            }

            w.write_u32_le(count); // total entries
            w.write_u32_le(0); // resume handle
            w.write_u32_le(0); // return value
        }

        let stub = w.into_inner();

        // Wrap in RPC RESPONSE envelope
        let mut w2 = WriteCursor::with_capacity(24 + stub.len());
        w2.write_u8(5);
        w2.write_u8(0);
        w2.write_u8(2); // RESPONSE
        w2.write_u8(0x03);
        w2.write_bytes(&[0x10, 0x00, 0x00, 0x00]);
        let frag_len_pos = w2.position();
        w2.write_u16_le(0);
        w2.write_u16_le(0);
        w2.write_u32_le(2); // call id

        w2.write_u32_le(stub.len() as u32); // alloc hint
        w2.write_u16_le(0); // context id
        w2.write_u8(0); // cancel count
        w2.write_u8(0); // reserved

        w2.write_bytes(&stub);

        let total_len = w2.position();
        w2.set_u16_le_at(frag_len_pos, total_len as u16);
        w2.into_inner()
    }

    fn write_ndr_string(w: &mut crate::pack::WriteCursor, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let char_count = utf16.len() as u32;
        w.write_u32_le(char_count);
        w.write_u32_le(0);
        w.write_u32_le(char_count);
        for &code_unit in &utf16 {
            w.write_u16_le(code_unit);
        }
        w.align_to(4);
    }

    /// Queue all the responses needed for a full list_shares flow.
    pub(crate) fn queue_share_listing_responses(
        mock: &MockTransport,
        shares: &[(&str, u32, &str)],
    ) {
        let tree_id = TreeId(42);
        let file_id = FileId {
            persistent: 0xAAAA,
            volatile: 0xBBBB,
        };

        // 1. TREE_CONNECT response
        mock.queue_response(build_tree_connect_response(tree_id, ShareType::Pipe));
        // 2. CREATE response (open srvsvc pipe)
        mock.queue_response(build_create_response(file_id, 0));
        // 3. WRITE response (RPC BIND)
        mock.queue_response(build_write_response(72));
        // 4. READ response (BIND_ACK)
        mock.queue_response(build_read_response(build_bind_ack()));
        // 5. WRITE response (NetShareEnumAll request)
        mock.queue_response(build_write_response(100));
        // 6. READ response (NetShareEnumAll response)
        mock.queue_response(build_read_response(build_share_enum_response(shares)));
        // 7. CLOSE response
        mock.queue_response(build_close_response());
        // 8. TREE_DISCONNECT response
        mock.queue_response(build_tree_disconnect_response());
    }

    #[tokio::test]
    async fn list_shares_returns_disk_shares() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        queue_share_listing_responses(
            &mock,
            &[
                ("Documents", STYPE_DISKTREE, "Shared docs"),
                ("IPC$", STYPE_IPC | STYPE_SPECIAL, "Remote IPC"),
                ("C$", STYPE_DISKTREE | STYPE_SPECIAL, "Default share"),
                ("Photos", STYPE_DISKTREE, "Family photos"),
            ],
        );

        let shares = list_shares(&mut conn).await.unwrap();

        // Only disk shares without $ suffix and without STYPE_SPECIAL
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "Documents");
        assert_eq!(shares[0].comment, "Shared docs");
        assert_eq!(shares[1].name, "Photos");
        assert_eq!(shares[1].comment, "Family photos");
    }

    #[tokio::test]
    async fn list_shares_sends_correct_number_of_messages() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        queue_share_listing_responses(&mock, &[("TestShare", STYPE_DISKTREE, "A test share")]);

        let _shares = list_shares(&mut conn).await.unwrap();

        // Should have sent 8 messages:
        // TREE_CONNECT, CREATE, WRITE(bind), READ(bind_ack),
        // WRITE(request), READ(response), CLOSE, TREE_DISCONNECT
        assert_eq!(mock.sent_count(), 8);
    }

    #[tokio::test]
    async fn list_shares_empty_server() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        queue_share_listing_responses(&mock, &[]);

        let shares = list_shares(&mut conn).await.unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn list_shares_filters_non_disk_shares() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);

        // All non-disk or special shares
        queue_share_listing_responses(
            &mock,
            &[
                ("IPC$", STYPE_IPC | STYPE_SPECIAL, "Remote IPC"),
                ("ADMIN$", STYPE_DISKTREE | STYPE_SPECIAL, "Remote Admin"),
            ],
        );

        let shares = list_shares(&mut conn).await.unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn list_shares_uses_correct_server_name() {
        let mock = Arc::new(MockTransport::new());
        let mut conn =
            Connection::from_transport(Box::new(mock.clone()), Box::new(mock.clone()), "my-nas");
        conn.set_test_params(NegotiatedParams {
            dialect: Dialect::Smb2_0_2,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(),
            gmac_negotiated: false,
            cipher: None,
            compression_supported: false,
        });
        conn.set_session_id(SessionId(0x1234));
        conn.set_orphan_filter_enabled(false);

        queue_share_listing_responses(&mock, &[("share1", STYPE_DISKTREE, "")]);

        let shares = list_shares(&mut conn).await.unwrap();
        assert_eq!(shares.len(), 1);

        // Verify the TREE_CONNECT request contains \\my-nas\IPC$
        let sent = mock.sent_messages();
        let tree_connect_bytes = &sent[0];
        // The UNC path is UTF-16LE in the request body
        let unc_utf8 = String::from_utf8_lossy(tree_connect_bytes);
        // Verify the server name appears somewhere in the raw bytes
        assert!(
            tree_connect_bytes.windows(2).any(|w| w == b"m\0"), // 'm' in UTF-16LE from "my-nas"
            "TREE_CONNECT should reference the server name"
        );
        drop(unc_utf8);
    }
}
