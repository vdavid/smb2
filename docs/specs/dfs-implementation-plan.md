# DFS implementation plan

Reviewed 5 rounds by independent Opus agents. 21 issues found and resolved.

## Architecture

DFS is a resolver layer at the SmbClient level that translates DFS namespace paths to real
server/share/path targets. Reactive (triggers on STATUS_PATH_NOT_COVERED), transparent to callers.

```
SmbClient
  ├── connections: HashMap<"host:port", ConnectionEntry>  // pool
  ├── tree_cache: HashMap<(server, share), Tree>
  ├── dfs_resolver: DfsResolver  // referral cache with TTL
  └── primary_server: String
```

## Key decisions

| Decision | Why | Rejected alternative |
|---|---|---|
| Reactive resolution (not proactive) | Standalone DFS namespaces tree-connect fine; links discovered on access | Proactive at connect_share — only for domain DFS |
| Connection pool (not replace self.conn) | Replacing invalidates existing Trees | Single connection — breaks multi-share |
| DFS flag via HashSet<TreeId> | Auto-set in send_request + send_compound. Zero signature changes | is_dfs param threading — 30+ call sites |
| &mut Tree in convenience methods | In-place update on redirect; next call goes direct | &Tree — can't update, re-resolves every time |
| Port 445 default for DFS targets | UNC paths don't include ports; 445 universal in production | Port inheritance — zero benefit |
| Multi-target failover | Try each target until one connects; ~20 lines in handle_dfs_redirect | Deferred — but smb-rs has it, so we should too |

## Explicit deferrals

- Proactive/domain-based DFS (needs AD DC)
- Chained referrals (multi-hop DFS rare)
- Target failback (V4 feature, needs health checking)
- Pipeline DFS (returns PATH_NOT_COVERED as-is)
- Non-445 DFS targets

## Steps

### 1. Wire format (src/msg/dfs.rs)
ReqGetDfsReferral + RespGetDfsReferral + DfsReferralEntry (V2-V4 flattened).
Test with known bytes from smb-rs.

### 2. DFS flag auto-set (src/client/connection.rs)
HashSet<TreeId> in Connection. Shared helper for send_request_with_credits AND send_compound.
Register on Tree::connect, remove on Tree::disconnect.

### 3. DFS referral IOCTL helper (src/client/dfs.rs)
get_dfs_referral(conn, ipc_tree_id, path). IPC$ cached in ConnectionEntry.

### 4. DFS resolver + cache (src/client/dfs.rs)
DfsResolver with HashMap cache, TTL, longest-prefix match. Path normalization via
PathConsumed bytes (UTF-16LE decode, not N/2 chars).

### 5. Connection pool + Tree.server + tree cache (src/client/mod.rs)
HashMap<String, ConnectionEntry> keyed by host:port. Tree gets server field.
tree_cache: HashMap<(String, String), Tree>.

### 6. Reactive DFS + multi-target failover in convenience methods (src/client/mod.rs)
&mut Tree. Explicit match per method. handle_dfs_redirect resolves, tries each target
until one connects, creates/reuses connection+tree, updates *tree in-place, retries once.

### 7. Docker tests (2 containers) + docs
smb-dfs-root:10456, smb-dfs-target:10457. Update CLAUDE.md, AGENTS.md, README.md.
