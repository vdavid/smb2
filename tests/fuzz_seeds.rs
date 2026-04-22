//! Seed-corpus generator for the `fuzz/` crate.
//!
//! This is not a real test. It's `#[ignore]`d by default and runs only when
//! invoked explicitly (`cargo test --test fuzz_seeds -- --ignored`). When
//! run, it writes hand-constructed valid instances of wire-format types
//! into `fuzz/corpus/<target>/seed_*.bin`, giving libfuzzer a strong
//! starting point so it doesn't waste the first hour rediscovering "here's
//! what a valid SMB2 frame looks like."
//!
//! Keep these seeds tiny and diverse: a couple dozen per target is plenty,
//! libfuzzer mutates from there. The goal is coverage of the interesting
//! branches (async vs sync, response vs request, each Command, each
//! NegotiateContext variant, etc.), not realistic traffic capture.

#![allow(clippy::pedantic)]

use std::fs;
use std::path::{Path, PathBuf};

use smb2::msg::create::{
    CreateAction, CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use smb2::msg::header::Header;
use smb2::msg::negotiate::{
    NegotiateContext, NegotiateRequest, NegotiateResponse, HASH_ALGORITHM_SHA512,
};
use smb2::msg::query_info::QueryInfoResponse;
use smb2::msg::transform::{CompressionTransformHeader, TransformHeader};
use smb2::pack::{FileTime, Guid, Pack, WriteCursor};
use smb2::types::flags::{Capabilities, FileAccessMask, HeaderFlags, SecurityMode};
use smb2::types::{
    status::NtStatus, Command, CreditCharge, Dialect, MessageId, OplockLevel, SessionId, TreeId,
};

fn corpus_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("fuzz").join("corpus")
}

fn write_seed(target: &str, name: &str, bytes: &[u8]) {
    let dir = corpus_root().join(target);
    fs::create_dir_all(&dir).expect("create corpus dir");
    let path = dir.join(format!("seed_{name}.bin"));
    fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

fn pack_bytes<P: Pack>(value: &P) -> Vec<u8> {
    let mut cursor = WriteCursor::new();
    value.pack(&mut cursor);
    cursor.into_inner()
}

// ── Seed constructors ───────────────────────────────────────────────────

fn sync_header(command: Command, is_response: bool) -> Header {
    let mut h = Header::new_request(command);
    h.credits = 32;
    h.message_id = MessageId(7);
    h.session_id = SessionId(0xDEAD_BEEF);
    h.tree_id = Some(TreeId(0x0A0B));
    if is_response {
        h.flags.set_response();
        h.status = NtStatus::SUCCESS;
    }
    h
}

fn async_header(command: Command) -> Header {
    let mut flags = HeaderFlags::default();
    flags.set_async();
    flags.set_response();
    Header {
        credit_charge: CreditCharge(1),
        status: NtStatus::PENDING,
        command,
        credits: 1,
        flags,
        next_command: 0,
        message_id: MessageId(8),
        tree_id: None,
        async_id: Some(0x0102_0304),
        session_id: SessionId(0x0853_27D7),
        signature: [0u8; 16],
    }
}

fn file_id(persistent: u64, volatile: u64) -> smb2::types::FileId {
    smb2::types::FileId {
        persistent,
        volatile,
    }
}

fn build_negotiate_response(dialect: Dialect) -> Vec<u8> {
    let resp = NegotiateResponse {
        security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
        dialect_revision: dialect,
        server_guid: Guid::ZERO,
        capabilities: Capabilities::new(Capabilities::DFS | Capabilities::LEASING),
        max_transact_size: 65536,
        max_read_size: 65536,
        max_write_size: 65536,
        system_time: 132_000_000_000_000_000,
        server_start_time: 131_000_000_000_000_000,
        security_buffer: vec![0x60, 0x00, 0xA1, 0x02],
        negotiate_contexts: if dialect == Dialect::Smb3_1_1 {
            vec![NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                salt: vec![0xAB; 32],
            }]
        } else {
            vec![]
        },
    };
    pack_bytes(&resp)
}

fn build_simple_create_response() -> Vec<u8> {
    let resp = CreateResponse {
        oplock_level: OplockLevel::None,
        flags: 0,
        create_action: CreateAction::FileOpened,
        creation_time: FileTime(0),
        last_access_time: FileTime(0),
        last_write_time: FileTime(0),
        change_time: FileTime(0),
        allocation_size: 0,
        end_of_file: 0,
        file_attributes: 0x20, // FILE_ATTRIBUTE_ARCHIVE
        file_id: file_id(0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
        create_contexts: Vec::new(),
    };
    pack_bytes(&resp)
}

// Build a compound frame: two SMB2 sub-responses chained via NextCommand.
fn build_compound_two() -> Vec<u8> {
    // Sub 1: an Echo response (tiny body).
    let h1 = sync_header(Command::Echo, true);
    let mut sub1 = pack_bytes(&h1);
    let body1 = pack_bytes(&smb2::msg::echo::EchoResponse);
    sub1.extend_from_slice(&body1);

    // 8-byte-align sub1
    let remainder = sub1.len() % 8;
    if remainder != 0 {
        sub1.resize(sub1.len() + (8 - remainder), 0);
    }
    let next_cmd = sub1.len() as u32;
    // NextCommand lives at offset 20..24 in the header.
    sub1[20..24].copy_from_slice(&next_cmd.to_le_bytes());

    // Sub 2: Echo response (no NextCommand advance).
    let h2 = sync_header(Command::Echo, true);
    let mut sub2 = pack_bytes(&h2);
    let body2 = pack_bytes(&smb2::msg::echo::EchoResponse);
    sub2.extend_from_slice(&body2);

    let mut frame = sub1;
    frame.extend_from_slice(&sub2);
    frame
}

// A malformed-but-close compound: NextCommand points past the buffer.
fn build_compound_truncated() -> Vec<u8> {
    let h = sync_header(Command::Echo, true);
    let mut sub = pack_bytes(&h);
    sub.extend_from_slice(&pack_bytes(&smb2::msg::echo::EchoResponse));
    // NextCommand = 9999 (way past).
    sub[20..24].copy_from_slice(&9999u32.to_le_bytes());
    sub
}

fn build_transform_header() -> Vec<u8> {
    let h = TransformHeader {
        signature: [0xAA; 16],
        nonce: [0xBB; 16],
        original_message_size: 256,
        flags: 0x0001,
        session_id: SessionId(0x1234_5678),
    };
    pack_bytes(&h)
}

fn build_compression_transform_header() -> Vec<u8> {
    let h = CompressionTransformHeader {
        original_compressed_segment_size: 1024,
        compression_algorithm: 5, // LZ4
        flags: 0,
        offset_or_length: 0,
    };
    pack_bytes(&h)
}

fn build_query_info_response() -> Vec<u8> {
    let resp = QueryInfoResponse {
        output_buffer: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };
    pack_bytes(&resp)
}

fn build_dfs_referral_empty() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0u16.to_le_bytes()); // path_consumed
    buf.extend_from_slice(&0u16.to_le_bytes()); // number_of_referrals
    buf.extend_from_slice(&0u32.to_le_bytes()); // header_flags
    buf
}

fn build_dfs_referral_v4() -> Vec<u8> {
    // Minimal V4 entry pointing at one target string.
    let target_name = "\\\\server\\share";
    let target_utf16: Vec<u8> = target_name
        .encode_utf16()
        .flat_map(|cu| cu.to_le_bytes().to_vec())
        .chain([0u8, 0u8]) // null terminator
        .collect();

    let entry_fixed_size: u16 = 34; // 4 + 2+2+4 + 2+2+2 + 16
    let same_ptr_offset = entry_fixed_size;

    let mut buf = Vec::new();
    buf.extend_from_slice(&16u16.to_le_bytes()); // path_consumed
    buf.extend_from_slice(&1u16.to_le_bytes()); // number_of_referrals
    buf.extend_from_slice(&0u32.to_le_bytes()); // header_flags

    // Entry
    buf.extend_from_slice(&4u16.to_le_bytes()); // version
    buf.extend_from_slice(&entry_fixed_size.to_le_bytes()); // size
    buf.extend_from_slice(&0u16.to_le_bytes()); // server_type
    buf.extend_from_slice(&0u16.to_le_bytes()); // referral_entry_flags
    buf.extend_from_slice(&1800u32.to_le_bytes()); // ttl
    buf.extend_from_slice(&same_ptr_offset.to_le_bytes()); // dfs_path_offset
    buf.extend_from_slice(&same_ptr_offset.to_le_bytes()); // alt_path_offset
    buf.extend_from_slice(&same_ptr_offset.to_le_bytes()); // net_addr_offset
    buf.extend_from_slice(&[0u8; 16]); // service_site_guid

    // Strings
    buf.extend_from_slice(&target_utf16);

    buf
}

#[test]
#[ignore = "run explicitly: cargo test --test fuzz_seeds -- --ignored"]
fn generate_fuzz_seeds() {
    // ── fuzz_header_parse ───────────────────────────────────────────
    for (i, cmd) in [
        Command::Negotiate,
        Command::SessionSetup,
        Command::Create,
        Command::Read,
        Command::Write,
        Command::Ioctl,
        Command::QueryDirectory,
        Command::QueryInfo,
    ]
    .iter()
    .enumerate()
    {
        let h = sync_header(*cmd, i % 2 == 0);
        write_seed(
            "fuzz_header_parse",
            &format!("sync_{:02}", i),
            &pack_bytes(&h),
        );
    }
    write_seed(
        "fuzz_header_parse",
        "async_changenotify",
        &pack_bytes(&async_header(Command::ChangeNotify)),
    );
    write_seed(
        "fuzz_header_parse",
        "async_ioctl",
        &pack_bytes(&async_header(Command::Ioctl)),
    );

    // ── fuzz_transform_header_parse ────────────────────────────────
    write_seed(
        "fuzz_transform_header_parse",
        "00",
        &build_transform_header(),
    );

    // ── fuzz_compression_transform_header_parse ────────────────────
    write_seed(
        "fuzz_compression_transform_header_parse",
        "00",
        &build_compression_transform_header(),
    );

    // ── fuzz_compound_split ─────────────────────────────────────────
    write_seed("fuzz_compound_split", "two", &build_compound_two());
    write_seed("fuzz_compound_split", "trunc", &build_compound_truncated());
    {
        // single echo response, NextCommand=0
        let h = sync_header(Command::Echo, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&pack_bytes(&smb2::msg::echo::EchoResponse));
        write_seed("fuzz_compound_split", "single_echo", &b);
    }

    // ── fuzz_frame_parse ────────────────────────────────────────────
    write_seed("fuzz_frame_parse", "two", &build_compound_two());
    {
        let h = sync_header(Command::Create, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&build_simple_create_response());
        write_seed("fuzz_frame_parse", "single_create", &b);
    }

    // ── fuzz_sub_frame_parse ────────────────────────────────────────
    {
        let h = sync_header(Command::Negotiate, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&build_negotiate_response(Dialect::Smb3_1_1));
        write_seed("fuzz_sub_frame_parse", "negotiate_response_311", &b);
    }
    {
        let h = sync_header(Command::Negotiate, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&build_negotiate_response(Dialect::Smb2_1));
        write_seed("fuzz_sub_frame_parse", "negotiate_response_210", &b);
    }
    {
        let h = sync_header(Command::Create, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&build_simple_create_response());
        write_seed("fuzz_sub_frame_parse", "create_response", &b);
    }
    {
        let h = sync_header(Command::QueryInfo, true);
        let mut b = pack_bytes(&h);
        b.extend_from_slice(&build_query_info_response());
        write_seed("fuzz_sub_frame_parse", "query_info_response", &b);
    }

    // ── fuzz_negotiate_request_parse ────────────────────────────────
    {
        let req = NegotiateRequest {
            dialects: vec![
                Dialect::Smb2_0_2,
                Dialect::Smb2_1,
                Dialect::Smb3_0,
                Dialect::Smb3_1_1,
            ],
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            capabilities: Capabilities::new(Capabilities::DFS),
            client_guid: Guid::ZERO,
            negotiate_contexts: vec![NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                salt: vec![0x11; 32],
            }],
        };
        write_seed("fuzz_negotiate_request_parse", "311", &pack_bytes(&req));
    }
    {
        let req = NegotiateRequest {
            dialects: vec![Dialect::Smb2_1],
            security_mode: SecurityMode::new(0),
            capabilities: Capabilities::new(0),
            client_guid: Guid::ZERO,
            negotiate_contexts: vec![],
        };
        write_seed("fuzz_negotiate_request_parse", "simple", &pack_bytes(&req));
    }

    // ── fuzz_negotiate_response_parse ───────────────────────────────
    write_seed(
        "fuzz_negotiate_response_parse",
        "311",
        &build_negotiate_response(Dialect::Smb3_1_1),
    );
    write_seed(
        "fuzz_negotiate_response_parse",
        "300",
        &build_negotiate_response(Dialect::Smb3_0),
    );
    write_seed(
        "fuzz_negotiate_response_parse",
        "210",
        &build_negotiate_response(Dialect::Smb2_1),
    );

    // ── fuzz_create_request_parse ───────────────────────────────────
    {
        let req = CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask(0x0012_0089),
            file_attributes: 0,
            share_access: ShareAccess(
                ShareAccess::FILE_SHARE_READ
                    | ShareAccess::FILE_SHARE_WRITE
                    | ShareAccess::FILE_SHARE_DELETE,
            ),
            create_disposition: CreateDisposition::FileOpen,
            create_options: 0,
            name: "dir/file.txt".to_string(),
            create_contexts: Vec::new(),
        };
        write_seed("fuzz_create_request_parse", "simple", &pack_bytes(&req));
    }

    // ── fuzz_create_response_parse ──────────────────────────────────
    write_seed(
        "fuzz_create_response_parse",
        "simple",
        &build_simple_create_response(),
    );

    // ── fuzz_query_info_response_parse ──────────────────────────────
    write_seed(
        "fuzz_query_info_response_parse",
        "simple",
        &build_query_info_response(),
    );
    write_seed(
        "fuzz_query_info_response_parse",
        "empty",
        &pack_bytes(&QueryInfoResponse {
            output_buffer: Vec::new(),
        }),
    );

    // ── fuzz_dfs_referral_response_parse ────────────────────────────
    write_seed(
        "fuzz_dfs_referral_response_parse",
        "empty",
        &build_dfs_referral_empty(),
    );
    write_seed(
        "fuzz_dfs_referral_response_parse",
        "v4",
        &build_dfs_referral_v4(),
    );

    // Report out.
    let root = corpus_root();
    let mut count = 0usize;
    walk_count(&root, &mut count);
    eprintln!("generated {count} seed files under {}", root.display());
}

fn walk_count(path: &Path, count: &mut usize) {
    if let Ok(rd) = fs::read_dir(path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk_count(&p, count);
            } else if p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("seed_"))
                .unwrap_or(false)
            {
                *count += 1;
            }
        }
    }
}
