//! DFS referral IOCTL helper and path resolver with referral cache.
//!
//! Sends `FSCTL_DFS_GET_REFERRALS` via IOCTL to resolve DFS paths. Connects
//! to IPC$ for the IOCTL exchange, similar to how `shares.rs` does for RPC.
//!
//! The [`DfsResolver`] caches referral responses with TTL and resolves UNC
//! paths using longest-prefix matching. All string comparisons are
//! case-insensitive (DFS paths are case-insensitive per MS-DFSC).

// DFS resolver is used by SmbClient for reactive DFS path resolution.

use std::collections::HashMap;
use std::time::{Duration, Instant};

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

    let frame = conn.execute(Command::TreeConnect, &req, None).await?;

    if frame.header.command != Command::TreeConnect {
        return Err(Error::invalid_data(format!(
            "expected TreeConnect response, got {:?}",
            frame.header.command
        )));
    }

    if frame.header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: frame.header.status,
            command: Command::TreeConnect,
        });
    }

    let mut cursor = ReadCursor::new(&frame.body);
    let _resp = TreeConnectResponse::unpack(&mut cursor)?;

    let tree_id = frame
        .header
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

    let frame = conn
        .execute(Command::Ioctl, &ioctl_req, Some(tree_id))
        .await?;

    if frame.header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: frame.header.status,
            command: Command::Ioctl,
        });
    }

    // Parse the IOCTL response envelope
    let mut cursor = ReadCursor::new(&frame.body);
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
    let frame = conn
        .execute(Command::TreeDisconnect, &body, Some(tree_id))
        .await?;

    if frame.header.status != NtStatus::SUCCESS {
        return Err(Error::Protocol {
            status: frame.header.status,
            command: Command::TreeDisconnect,
        });
    }

    debug!("dfs: disconnected from IPC$");
    Ok(())
}

// ── DFS resolver types ───────────────────────────────────────────────

/// A resolved DFS path ready for connection.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedPath {
    /// Server hostname (or IP) to connect to.
    pub server: String,
    /// Port to connect on (default 445).
    pub port: u16,
    /// Share name to tree-connect.
    pub share: String,
    /// Remaining path within the share (may be empty).
    pub remaining_path: String,
}

/// A single DFS target from a referral response.
#[derive(Debug, Clone)]
struct DfsTarget {
    /// Server hostname from the network_address field.
    server: String,
    /// Share name from the network_address field.
    share: String,
    /// Any remaining path suffix from the network_address.
    remaining_prefix: String,
}

/// A cached DFS referral entry with TTL.
#[derive(Debug, Clone)]
struct CachedReferral {
    /// The DFS path prefix this referral covers (lowercase for matching).
    dfs_path_prefix: String,
    /// Available targets (first is preferred).
    targets: Vec<DfsTarget>,
    /// When this entry expires.
    expires_at: Instant,
}

/// DFS referral cache and path resolver.
///
/// Maintains a cache of DFS referral responses keyed by path prefix.
/// Resolves UNC paths by longest-prefix matching against the cache,
/// falling back to an IOCTL referral request on cache miss.
pub(crate) struct DfsResolver {
    cache: HashMap<String, CachedReferral>,
}

impl DfsResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Resolve a UNC path by checking the cache first, then querying the server.
    ///
    /// `unc_path` should be like `\\server\share\path\to\file`.
    /// `conn` is the connection to the server that returned `STATUS_PATH_NOT_COVERED`.
    pub async fn resolve(
        &mut self,
        conn: &mut Connection,
        unc_path: &str,
    ) -> Result<Vec<ResolvedPath>> {
        // 1. Check cache (longest prefix match)
        if let Some(resolved) = self.resolve_from_cache(unc_path) {
            debug!("dfs: cache hit for {:?}", unc_path);
            return Ok(resolved);
        }

        // 2. Send referral request.
        // Convert \\server\share\path to \server\share\path (single leading
        // backslash for the IOCTL).
        let referral_path = if unc_path.starts_with("\\\\") {
            &unc_path[1..] // strip one leading backslash
        } else {
            unc_path
        };

        debug!("dfs: cache miss, sending referral for {:?}", referral_path);
        let resp = get_dfs_referral(conn, referral_path).await?;

        // 3. Cache the result
        self.cache_referral(&resp);

        // 4. Resolve from the freshly cached entry
        self.resolve_from_cache(unc_path).ok_or_else(|| {
            Error::invalid_data("DFS referral response did not match the requested path")
        })
    }

    /// Try to resolve a path from the cache. Returns `None` on cache miss or
    /// expiry. Returns a `Vec` of [`ResolvedPath`]s (multiple targets for
    /// failover).
    pub(crate) fn resolve_from_cache(&self, unc_path: &str) -> Option<Vec<ResolvedPath>> {
        let normalized = unc_path.to_lowercase().replace('/', "\\");

        // Longest prefix match
        let mut best_match: Option<&CachedReferral> = None;
        for entry in self.cache.values() {
            if normalized.starts_with(&entry.dfs_path_prefix)
                && entry.expires_at > Instant::now()
                && best_match.is_none_or(|b| entry.dfs_path_prefix.len() > b.dfs_path_prefix.len())
            {
                best_match = Some(entry);
            }
        }

        let entry = best_match?;

        // Strip the consumed prefix and build ResolvedPaths
        let remaining = &normalized[entry.dfs_path_prefix.len()..];
        let remaining = remaining.trim_start_matches('\\');

        let resolved: Vec<ResolvedPath> = entry
            .targets
            .iter()
            .map(|target| {
                let full_remaining = if target.remaining_prefix.is_empty() {
                    remaining.to_string()
                } else if remaining.is_empty() {
                    target.remaining_prefix.clone()
                } else {
                    format!("{}\\{}", target.remaining_prefix, remaining)
                };

                ResolvedPath {
                    server: target.server.clone(),
                    port: 445,
                    share: target.share.clone(),
                    remaining_path: full_remaining,
                }
            })
            .collect();

        Some(resolved)
    }

    /// Store a referral response in the cache.
    fn cache_referral(&mut self, resp: &RespGetDfsReferral) {
        if resp.entries.is_empty() {
            return;
        }

        // Use the dfs_path from the first entry as the cache key.
        // Normalize to lowercase backslash form with `\\` prefix (UNC canonical).
        let mut dfs_path_prefix = resp.entries[0].dfs_path.to_lowercase().replace('/', "\\");
        if !dfs_path_prefix.starts_with("\\\\") {
            if let Some(stripped) = dfs_path_prefix.strip_prefix('\\') {
                dfs_path_prefix = format!("\\\\{stripped}");
            }
        }

        // Parse targets from entries
        let targets: Vec<DfsTarget> = resp
            .entries
            .iter()
            .filter_map(|e| parse_unc_target(&e.network_address))
            .collect();

        if targets.is_empty() {
            return;
        }

        let ttl = resp.entries[0].ttl.max(1); // At least 1 second

        debug!(
            "dfs: caching {:?} with {} targets, ttl={}s",
            dfs_path_prefix,
            targets.len(),
            ttl
        );

        self.cache.insert(
            dfs_path_prefix.clone(),
            CachedReferral {
                dfs_path_prefix,
                targets,
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }
}

/// Parse a UNC network_address into server, share, and remaining path.
///
/// Input: `\\server\share` or `\\server\share\path`.
/// Returns `None` if the format is invalid.
fn parse_unc_target(network_address: &str) -> Option<DfsTarget> {
    let path = network_address.trim_start_matches('\\');
    let mut parts = path.splitn(3, '\\');
    let server = parts.next()?.to_string();
    let share = parts.next()?.to_string();
    let remaining_prefix = parts.next().unwrap_or("").to_string();

    if server.is_empty() || share.is_empty() {
        return None;
    }

    Some(DfsTarget {
        server,
        share,
        remaining_prefix,
    })
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

    // ── parse_unc_target tests ───────────────────────────────────────

    #[test]
    fn parse_unc_target_basic() {
        let t = parse_unc_target(r"\\server\share").unwrap();
        assert_eq!(t.server, "server");
        assert_eq!(t.share, "share");
        assert_eq!(t.remaining_prefix, "");
    }

    #[test]
    fn parse_unc_target_with_path() {
        let t = parse_unc_target(r"\\server\share\path\to").unwrap();
        assert_eq!(t.server, "server");
        assert_eq!(t.share, "share");
        assert_eq!(t.remaining_prefix, r"path\to");
    }

    #[test]
    fn parse_unc_target_invalid() {
        assert!(parse_unc_target(r"\\").is_none());
        assert!(parse_unc_target("").is_none());
        assert!(parse_unc_target(r"\\server").is_none());
        // Single backslash + server but no share
        assert!(parse_unc_target(r"\server").is_none());
    }

    #[test]
    fn parse_unc_target_single_backslash_prefix() {
        // Network addresses with single backslash prefix should also work.
        let t = parse_unc_target(r"\server\share").unwrap();
        assert_eq!(t.server, "server");
        assert_eq!(t.share, "share");
        assert_eq!(t.remaining_prefix, "");
    }

    #[test]
    fn parse_unc_target_triple_backslash() {
        // Extra leading backslashes are stripped.
        let t = parse_unc_target(r"\\\server\share\path").unwrap();
        assert_eq!(t.server, "server");
        assert_eq!(t.share, "share");
        assert_eq!(t.remaining_prefix, "path");
    }

    #[test]
    fn parse_unc_target_ip_address() {
        // IP addresses as server names.
        let t = parse_unc_target(r"\\192.168.1.100\data").unwrap();
        assert_eq!(t.server, "192.168.1.100");
        assert_eq!(t.share, "data");
        assert_eq!(t.remaining_prefix, "");
    }

    #[test]
    fn parse_unc_target_deep_path() {
        // The remaining prefix captures everything after server\share.
        let t = parse_unc_target(r"\\server\share\a\b\c\d").unwrap();
        assert_eq!(t.server, "server");
        assert_eq!(t.share, "share");
        assert_eq!(t.remaining_prefix, r"a\b\c\d");
    }

    #[test]
    fn parse_unc_target_empty_components() {
        // Empty server or share should return None.
        assert!(parse_unc_target(r"\\\\share").is_none()); // empty server
        assert!(parse_unc_target(r"\\\").is_none()); // server is empty after strip
    }

    // ── DfsResolver tests ────────────────────────────────────────────

    /// Helper: build a RespGetDfsReferral for cache tests.
    fn make_referral(
        dfs_path: &str,
        entries: &[(&str, u32)], // (network_address, ttl)
    ) -> RespGetDfsReferral {
        use crate::msg::dfs::DfsReferralEntry;

        let referral_entries: Vec<DfsReferralEntry> = entries
            .iter()
            .map(|(net_addr, ttl)| DfsReferralEntry {
                version: 3,
                server_type: 0,
                referral_entry_flags: 0,
                ttl: *ttl,
                dfs_path: dfs_path.to_string(),
                dfs_alternate_path: dfs_path.to_string(),
                network_address: net_addr.to_string(),
            })
            .collect();

        RespGetDfsReferral {
            path_consumed: 0,
            header_flags: 0,
            entries: referral_entries,
        }
    }

    #[test]
    fn resolver_cache_hit() {
        let mut resolver = DfsResolver::new();

        let resp = make_referral(r"\domain\dfs\docs", &[(r"\\server1\share", 600)]);
        resolver.cache_referral(&resp);

        let result = resolver.resolve_from_cache(r"\\domain\dfs\docs\file.txt");
        assert!(result.is_some());
        let paths = result.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].server, "server1");
        assert_eq!(paths[0].share, "share");
        assert_eq!(paths[0].port, 445);
        assert_eq!(paths[0].remaining_path, "file.txt");
    }

    #[test]
    fn resolver_cache_miss() {
        let resolver = DfsResolver::new();

        let result = resolver.resolve_from_cache(r"\\server\share\file.txt");
        assert!(result.is_none());
    }

    #[test]
    fn resolver_cache_expired() {
        let mut resolver = DfsResolver::new();

        // Insert with TTL=0 -- cache_referral clamps to 1s, so we need to
        // manually insert an already-expired entry.
        let targets = vec![DfsTarget {
            server: "srv".to_string(),
            share: "data".to_string(),
            remaining_prefix: String::new(),
        }];
        resolver.cache.insert(
            r"\domain\dfs".to_string(),
            CachedReferral {
                dfs_path_prefix: r"\domain\dfs".to_string(),
                targets,
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );

        let result = resolver.resolve_from_cache(r"\\domain\dfs\file.txt");
        assert!(result.is_none(), "expired entry should not match");
    }

    #[test]
    fn resolver_cache_longest_prefix() {
        let mut resolver = DfsResolver::new();

        // Insert a short prefix
        let short = make_referral(r"\domain\dfs", &[(r"\\server1\root", 600)]);
        resolver.cache_referral(&short);

        // Insert a longer prefix
        let long = make_referral(r"\domain\dfs\docs", &[(r"\\server2\docs", 600)]);
        resolver.cache_referral(&long);

        // Should match the longer prefix
        let result = resolver
            .resolve_from_cache(r"\\domain\dfs\docs\file.txt")
            .unwrap();
        assert_eq!(result[0].server, "server2");
        assert_eq!(result[0].share, "docs");
        assert_eq!(result[0].remaining_path, "file.txt");

        // A path that only matches the short prefix
        let result2 = resolver
            .resolve_from_cache(r"\\domain\dfs\other\file.txt")
            .unwrap();
        assert_eq!(result2[0].server, "server1");
        assert_eq!(result2[0].share, "root");
        assert_eq!(result2[0].remaining_path, r"other\file.txt");
    }

    #[test]
    fn resolver_multiple_targets() {
        let mut resolver = DfsResolver::new();

        let resp = make_referral(
            r"\domain\dfs\docs",
            &[(r"\\server1\share", 600), (r"\\server2\share", 300)],
        );
        resolver.cache_referral(&resp);

        let result = resolver
            .resolve_from_cache(r"\\domain\dfs\docs\file.txt")
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].server, "server1");
        assert_eq!(result[1].server, "server2");
        // Both should have the same remaining path
        assert_eq!(result[0].remaining_path, "file.txt");
        assert_eq!(result[1].remaining_path, "file.txt");
    }

    #[test]
    fn resolver_path_normalization() {
        let mut resolver = DfsResolver::new();

        // Cache with backslash-separated DFS path
        let resp = make_referral(r"\domain\dfs\docs", &[(r"\\server\share", 600)]);
        resolver.cache_referral(&resp);

        // Resolve with double-backslash prefix and mixed case
        let result = resolver
            .resolve_from_cache(r"\\DOMAIN\DFS\DOCS\Sub\File.txt")
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].server, "server");
        assert_eq!(result[0].share, "share");
        // remaining_path is lowercased because we normalize the full input
        assert_eq!(result[0].remaining_path, r"sub\file.txt");

        // Forward slashes should also work
        let result2 = resolver
            .resolve_from_cache(r"\\domain/dfs/docs/other.txt")
            .unwrap();
        assert_eq!(result2[0].remaining_path, "other.txt");
    }

    #[test]
    fn resolver_remaining_prefix_from_target() {
        let mut resolver = DfsResolver::new();

        // Target has a remaining prefix (network_address includes a subpath)
        let resp = make_referral(r"\domain\dfs\docs", &[(r"\\server\share\subdir", 600)]);
        resolver.cache_referral(&resp);

        // With additional path after the DFS prefix
        let result = resolver
            .resolve_from_cache(r"\\domain\dfs\docs\file.txt")
            .unwrap();
        assert_eq!(result[0].remaining_path, r"subdir\file.txt");

        // Without additional path -- just the target's remaining prefix
        let result2 = resolver.resolve_from_cache(r"\\domain\dfs\docs").unwrap();
        assert_eq!(result2[0].remaining_path, "subdir");
    }
}
