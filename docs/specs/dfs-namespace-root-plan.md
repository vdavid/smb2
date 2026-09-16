# DFS namespace roots, and the connect budget that hides the second server

Teach the crate to reach a **DFS namespace root** (`\\<domain>\<namespace>`), which cannot be tree-connected because it
is not a share on the server answering that name. Along the way, fix the referral parser and resolver gaps that the
same work exposes, and stop one dead IP address from eating the whole TCP connect budget on a multi-homed name.

`docs/specs/dfs-implementation-plan.md` is the prior art: it built the **reactive link** path (`STATUS_PATH_NOT_COVERED`
inside a share that tree-connects) and deliberately deferred everything here. This plan picks up that deferral.

This doc is the source of truth during implementation. When something drifts, update this doc rather than the code.

## Why

`\\lgs-net.com\aleu`, where `lgs-net.com` is an Active Directory domain name and `aleu` is a domain-based DFS
namespace, cannot be opened at all. The session to `lgs-net.com:445` comes up in 160 ms, negotiates SMB 3.1.1 with
`Capabilities(7)` (`DFS | LEASING | LARGE_MTU`), authenticates, and then TreeConnect on `aleu` returns
`STATUS_BAD_NETWORK_NAME` in ~150 ms, twice, deterministically. Share enumeration against the same host returns zero
disk shares, so nothing in the crate's surface can find the namespace either. macOS mounts the same path happily and
labels it `DFS_SHARE TRUE` with `SERVER_NAME lgs-net.com`.

Today's DFS support keys off `STATUS_PATH_NOT_COVERED`, which a server can only return once a share has tree-connected.
A namespace root never gets that far, so the whole resolver is unreachable for this shape. For a consumer this reads as
"the server exists, the share does not", which is the one thing that is not true.

Two servers with different `server_guid`s answered `lgs-net.com:445` in the same session, which is what an AD domain
name normally looks like: several domain controllers behind one name. That is the setting for the second problem in
this plan.

## What is verified, and how

Everything below was checked against the spec text and against a live server, on 2026-09-16. Findings that rest on a
single field report are marked.

**From MS-DFSC** (corpus copy of the Microsoft Open Specifications markdown; the repo's
`related-repos/openspecs/skills/windows-protocols/` tree is not checked out, see § "Open questions"):

- § 2.2.1.4 — a DFS root is `\\<ServerName>\<DFSName>` or `\\<DomainName>\<DFSName>`, and a domain-based namespace
  "MUST be referred to in either format, although the second format is preferred". So the failing path is the spec's
  own preferred form.
- § 3.1.4.1 step 5 — on a referral-cache miss the client looks the **first path component** up in its DomainCache.
  With no matching entry it "MUST use the first path component as the host name for DFS root referral request
  purposes" and goes to step 6. **A client that is not domain-joined has no DomainCache, so this is always the branch
  it takes.** DomainCache and BootstrapDC exist to find a reachable DC when the domain name itself is not directly
  usable; a client that already has a session to that name has nothing left to discover.
- § 3.1.4.2, `Type = ROOT` — `RequestFileName` is `\<domain>\<dfsname>` or `\<server>\<dfsname>`, `MaxReferralLevel`
  unrestricted. Exactly two path components, exactly what `connect_share` knows.
- § 3.1.4.1 step 1 — a path with only one component is never a DFS path. `\\server` alone needs no handling.
- § 4.3 and § 4.6 — for a domain-based **and** for a standalone root referral, Windows sets ReferralServers and
  StorageServers to 1 and `ServerType` to 1.
- § 3.1.5.4.5 — a response is an Interlink (the target lives in another namespace) when ReferralServers is 1 **and**
  StorageServers is 0, or when the target's first component is itself a known domain.
- § 3.1.5.4 — on `STATUS_BUFFER_OVERFLOW` the client SHOULD retry with a bigger buffer.
- § 2.2.5.3.2 — with the NameListReferral flag set, a V3/V4 entry's tail is `SpecialNameOffset` +
  `NumberOfExpandedNames` + `ExpandedNameOffset`, **not** the three path offsets.
- § 2.2.2 — "A DFS client MUST support DFS referral version 1 through the version number set in this field."

**From MS-SMB2:**

- § 3.3.5.7 — "If no share with a matching share name and server name is found, the server MUST fail the request with
  STATUS_BAD_NETWORK_NAME." This is the authoritative reason the field log says what it says, and it means the status
  is a contract rather than a Windows quirk.
- § 3.2.5.5 — `TreeConnect.IsDfsShare` comes from `SMB2_SHARE_CAP_DFS` in the response's **Capabilities**.
  `Tree::connect` already reads it from there, which is right.
- § 3.2.4.20.3 — a referral goes over **any** existing tree connect to that server, and only needs a fresh IPC$ tree
  when none exists. `FileId` must be all-`0xFF`.
- § 2.2.4 — `SMB2_GLOBAL_CAP_DFS` is `0x00000001` in the NEGOTIATE response capabilities, which the crate already
  parses into `NegotiatedParams::capabilities`.

**From a live Samba 4.20.6 (alpine 3.21) probe, run 2026-09-16** (this is the finding that reshapes the testing plan;
see § "Testing"):

A share declared with `msdfs root = yes` plus `msdfs proxy = \<host>\<share>` reproduces the field shape exactly.

- TreeConnect on it fails, and smbd says so in as many words:
  `smbd_smb2_tree_connect: refusing connection to dfs proxy share 'proxyns' (pointing to \dfstarget\files)`.
  The crate's own client reports `Protocol error: STATUS_BAD_NETWORK_NAME during TreeConnect`, byte for byte the
  consumer's log line.
- `FSCTL_DFS_GET_REFERRALS` for `\127.0.0.1\proxyns` over IPC$ returns, through the crate's existing parser:
  `path_consumed: 36, header_flags: 2, entries: [{ version: 3, server_type: 0, referral_entry_flags: 0, ttl: 600,
  dfs_path: "\\127.0.0.1\\proxyns", dfs_alternate_path: "\\127.0.0.1\\proxyns", network_address: "\\dfstarget\\files" }]`.
- `msdfs proxy` takes a comma-separated list, and the entries come back in configured order, so **multi-target
  failover is reproducible too**. Probing with `\nosuchhost\files,\dfstarget\files` returned both entries in that order.
- A referral for a share that does not exist at all returns `STATUS_NOT_FOUND` on the IOCTL.

Two divergences from Windows fall out of that, and both are load-bearing:

- **Samba answers a root referral with `ServerType = 0` and `header_flags = 0x02` (StorageServers only).** Windows, per
  § 4.3 and § 4.6, answers with `ServerType = 1` and both bits set. A client that requires `ServerType == 1` before
  accepting a root referral works against Windows and silently refuses Samba. ❌ Nothing in this plan may gate on
  `ServerType`.
- Samba's `header_flags = 0x02` is R=0, S=1, which is **not** an Interlink by the § 3.1.5.4.5 test. Good: the ordinary
  case stays one hop.

**From reading the code** (all confirmed by opening the files, not inferred):

- `TcpTransport::connect` wraps one `tokio::time::timeout` around `TcpStream::connect(addr)`, and tokio walks every
  address `getaddrinfo` returns underneath it. One unresponsive address exhausts the entire budget and the live ones
  are never dialled. The field log shows twelve dials to `lgs-net.com:445` each burning exactly 10.00 s with no
  `tcp: connected` line, interleaved with dials to the same `host:port` that connected in 4–22 ms, plus an
  `os error 65` (no route to host) on an IPv6 address. **The code shape is the finding; the log is consistent with it
  rather than proof of it.**
- `SmbClient::ensure_tree` calls `Tree::connect` and skips the share-encryption activation that `connect_share` does,
  so a DFS target share carrying `SMB2_SHAREFLAG_ENCRYPT_DATA` never gets encryption turned on.
- `DfsResolver::resolve_from_cache` lowercases the whole input and then slices the **lowercased** string for the
  remaining path. Its own test asserts this (`remaining_path is lowercased because we normalize the full input`).
- The same function matches with a raw `str::starts_with`, so `\\dom\ns` matches `\\dom\nsfoo\x`.
- `DfsResolver`'s cache is an unbounded `HashMap` whose expired entries are skipped on lookup and never removed.
- `msg::dfs::parse_referral_entry` rejects V1 outright and never inspects `ReferralEntryFlags` for NameListReferral.
- `get_dfs_referral` tree-connects and tree-disconnects IPC$ on every call, three frames per referral.
- `client::dfs` never reads `path_consumed` or `server_type` beyond parsing them, and `DfsResolver` discards
  `server_type` when it builds its targets.
- `ClientConfig` has no `Default` impl, so every field addition is a breaking change for callers writing a struct
  literal, which is all of them.

## Non-goals

- **No DC or domain referral requests.** § 3.1.4.1 only reaches for them when DomainCache says the first path
  component is a domain, which a non-domain-joined client never has. We parse NameListReferral entries so a response
  carrying them can never be mis-read, and we do not issue the requests. A NetBIOS-only domain name that DNS cannot
  resolve stays unsupported, and says so in the docs.
- **No namespace enumeration.** `\\lgs-net.com` legitimately has zero disk shares; MS-DFSC has no operation that lists
  the namespaces a domain hosts. That lives in MS-DFSNM (`NetrDfsEnumEx` over the `netdfs` pipe), a different protocol
  and a much larger lift. Document the limitation instead of half-solving it.
- **No `REQ_GET_DFS_REFERRAL_EX` / `FSCTL_DFS_GET_REFERRALS_EX`.** Its only payload is the client's AD site name
  (MS-DFSC § 2.2.3), which a non-domain-joined client does not know. Nothing is lost.
- **No target failback** (V4, § 3.1.5.4.3). It needs health checking of a preferred target we deliberately moved off.
  Target *failover* is in scope; failback is not.
- **No multi-channel, no SMB Direct.** Unrelated, and already listed as unsupported in `README.md`.
- **No DFS retry in the batch and streaming paths.** They document their own exclusion today and this plan does not
  change it.

## Part 1 — reaching a namespace root

### Where the trigger belongs

`SmbClient::connect_share` is the only place a caller-named share is tree-connected, and the only layer holding the
resolver, the connection pool, and the credentials. `Tree::connect` takes a bare `&mut Connection` and has none of
those, so it stays exactly as dumb as it is now.

The flow, following § 3.1.4.1 steps 2 and 5–8 with the DomainCache branch removed:

1. **Cache first.** Look `\\<server>\<share>` up in `DfsResolver`. On an unexpired hit, go straight to the target, so
   the wasted TreeConnect is paid once per TTL and not once per connect. This is § 3.1.4.1 step 2 and it is why the
   feature does not need a "proactive" mode.
2. **Otherwise TreeConnect**, as today. Success ends it, which is the entire non-DFS world at zero extra cost.
3. **On `STATUS_BAD_NETWORK_NAME`**, and only when `dfs_enabled` is on *and* the connection negotiated
   `SMB2_GLOBAL_CAP_DFS`, issue a ROOT referral for `\<server>\<share>` over IPC$ on the connection we already have.
4. **On a referral with at least one entry**, try each target in order: connect (pooled), tree-connect the target
   share, activate share encryption, done. First success wins.
5. **On anything else** — the server does not advertise DFS, the referral fails, the referral is empty, or every
   target is unreachable — the caller gets a truthful error. See below.

Deciding on the negotiated `CAP_DFS` bit keeps a plain NAS at zero extra round-trips when someone mistypes a share
name. A server that does advertise DFS pays three extra frames on an error path, which is a fair trade for the one
case that is currently impossible.

### What the caller sees when it does not work

❌ **A failed referral must not replace the original error.** The overwhelmingly common reason for
`STATUS_BAD_NETWORK_NAME` is a share name with a typo, and telling that user about DFS is worse than telling them
nothing. So:

- Referral fails, returns zero entries, or the server never advertised DFS → return the **original**
  `Error::Protocol { status: BAD_NETWORK_NAME, command: TreeConnect }`, with the referral outcome logged at `debug`.
- Referral succeeds and names targets, but none of them can be reached → a new, honest variant:

```rust
/// The path is a DFS namespace, and none of its targets could be reached.
#[error("DFS namespace {namespace} resolved to {target_count} target(s), none reachable")]
DfsNoReachableTarget {
    /// The namespace path the caller asked for, for example `\\lgs-net.com\aleu`.
    namespace: String,
    /// How many targets the referral offered.
    target_count: usize,
    /// Why the last one failed.
    source: Box<Error>,
},
```

That variant says something no existing error says: the namespace is real, we found it, the storage behind it is out of
reach. `Error` and `ErrorKind` are both `#[non_exhaustive]`, so adding it and an `ErrorKind::DfsNoReachableTarget` is
**not breaking**.

### Keeping the caller's own name for the share

After a redirect the `Tree` points at `\\fs01\aleu_dfs`, while the user asked for `\\lgs-net.com\aleu` and every other
client keeps showing them the latter (macOS reports `SERVER_NAME lgs-net.com` for exactly this mount). A library that
throws the requested name away forces every consumer to shadow it.

```rust
/// Where a tree came from, when a DFS referral put it somewhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsOrigin {
    /// The UNC path the caller asked for, for example `\\lgs-net.com\aleu`.
    pub requested: String,
    /// The referral target this tree actually sits on, for example `\\fs01\aleu_dfs`.
    pub target: String,
}

pub struct Tree {
    // ...
    /// `Some` when DFS resolution moved this tree off the path the caller named.
    pub dfs_origin: Option<DfsOrigin>,
}
```

**This is breaking**: `Tree`'s fields are all `pub` with no `#[non_exhaustive]`, so a struct literal outside the crate
stops compiling. Take the opportunity and mark `Tree` `#[non_exhaustive]` in the same release. `Tree` is only ever
produced by the library, never built by a consumer, so nothing of value is lost and every later field is free.
`ClientConfig` is genuinely consumer-constructed, so it gets an `impl Default` instead and stays literal-friendly.

### Cross-server targets, and what already works

`extra_connections`, `ensure_connection`, `ensure_tree`, and `connection_for_tree` already do the cross-server work for
the link case, and a root target is the same shape. Three gaps to close while we are here:

- `ensure_tree` skips share encryption. Extract the activation block from `connect_share` into one
  `activate_share_encryption(conn, session, tree)` helper and call it from both. A share that asked to be encrypted
  and is not is a data-confidentiality bug, not a convenience gap.
- `ensure_connection` sets no reviver, so `auto_reconnect` silently does not cover DFS target connections, and
  `recover_tree` returns `Error::Disconnected` for them. Arm each extra connection with a `ClientReviver` built from
  the same config, and let `recover_tree` handle a non-primary tree by reconnecting its own connection. Worth doing
  here because a namespace root makes the *target* connection the one carrying all the user's traffic.
- Bound the hops. A root referral whose target is an Interlink, or a mis-configured namespace that points at itself,
  should stop at `MAX_DFS_HOPS = 8` with a typed `Error::DfsTooManyReferrals { namespace, hops }` rather than
  recursing. One-hop Interlink handling (§ 3.1.5.4.5: R=1 and S=0, re-resolve the target as a fresh path) comes free
  once the loop exists.

### Referral versions

Ask for `MaxReferralLevel = 4` as today and accept whatever comes back. Verified live: Samba answers V3, and § 4.1
notes Windows answering V3 to a V4 request, so the "highest supported" field is a ceiling and never a demand.

- **V1** gets implemented. § 2.2.2 says a client MUST support every version up to the one it asks for, and the parser
  refusing V1 makes `MaxReferralLevel = 4` a false claim. The entry is `VersionNumber(2) + Size(2) + ServerType(2) +
  ReferralEntryFlags(2)` followed by an **inline** null-terminated `ShareName`, with no offsets and no `DFSPath`. That
  last part matters: a V1 response is the one case where the cache key has to come from `PathConsumed` against the
  request path rather than from `dfs_path`.
- **V2, V3, V4** already parse. V4 differs from V3 only in the version number and the `TargetSetBoundary` bit
  (§ 2.2.5.4), which we start storing so failover can prefer targets inside the first target set.
- **NameListReferral** (V3/V4 flag `0x0002`) gets a separate parse branch. Today a NameListReferral entry would be
  read as three path offsets and yield garbage strings from arbitrary buffer positions. We never request the referral
  types that produce it, so this is a robustness fix against a hostile or broken server rather than a live bug, and it
  belongs in the same pass as the fuzz target.

Model the two shapes as a sum type instead of a struct with conditionally-meaningful fields, so the wrong branch is
unrepresentable:

```rust
pub enum DfsReferralEntry {
    /// A root, link, or sysvol target.
    Target { version: u16, server_type: u16, flags: ReferralEntryFlags, ttl: u32,
             dfs_path: String, dfs_alternate_path: String, network_address: String },
    /// A domain or DC referral (NameListReferral set). Parsed so it cannot be
    /// mistaken for a target; never requested by this crate.
    NameList { version: u16, flags: ReferralEntryFlags, ttl: u32,
               special_name: String, expanded_names: Vec<String> },
}
```

Breaking for anyone matching on `DfsReferralEntry`'s fields. The type is `pub` in `msg::dfs` and exists to describe the
wire, so the honest shape wins over the compatible one.

### Caching and TTL

Keep `DfsResolver`, and grow it to what § 3.1.1's ReferralCache actually needs:

- **Store `RootOrLink`** (from `ServerType`) so `connect_share` can tell a root entry from a link entry, per
  § 3.1.4.1 steps 4 and 7. ❌ Store it, never gate on it — Samba reports `0` for a root referral.
- **Store `Interlink`** (the § 3.1.5.4.5 test) and `TargetFailback`, evaluated once at insert.
- **Key from `dfs_path` when present, from `PathConsumed` when it is not** (V1). `PathConsumed` counts **bytes of
  UTF-16LE**, so the prefix is the first `path_consumed / 2` code units of the request path, taken with
  `encode_utf16`, never `chars()` and never a byte slice.
- **Match on whole components.** `\\dom\ns` must not match `\\dom\nsfoo\x`: a hit requires the next character to be a
  separator or end-of-string.
- **Match case-insensitively, return the caller's case.** Compare on a lowercased copy, then slice the **original**
  string for the remaining path. The current behavior hands back `docs/report.pdf` for `Docs/Report.PDF`, which opens
  the wrong file (or nothing) on a case-sensitive export. Its test asserting the lowercasing gets inverted into a
  regression test.
- **Bound the cache** at a few hundred entries with expired-first eviction. It is keyed by server-supplied strings and
  currently grows forever.
- **`TargetHint`** (§ 3.1.1): remember which target last worked and try it first, so a failover survives the next
  lookup instead of re-walking the dead target every time.

TTL stays a single hard expiry. The spec's soft/hard split (§ 3.1.1, § 3.1.5.4.3) buys a background refresh we have no
scheduler for, and 600–1800 s TTLs make the saving small. Say so here rather than leaving it looking unconsidered.

### Referral plumbing

- **Reuse the IPC$ tree.** § 3.2.4.20.3 permits any existing tree connect and only asks for IPC$ when none exists.
  Cache one IPC$ `TreeId` per connection and drop the connect/disconnect pair from every referral. Three frames become
  one after the first.
- **Grow the buffer on overflow.** § 3.1.5.4 and MS-SMB2 § 3.3.5.15.2: on `STATUS_BUFFER_OVERFLOW` retry once with
  64 KiB. A namespace with many root targets overflows 8 KiB, and the current code turns that into a hard error.

## Part 2 — one connect budget per address

`TcpTransport::connect(addr: impl ToSocketAddrs, timeout)` puts a single deadline around a call that tries every
resolved address in sequence. Every AD domain name, and plenty of NASes, resolve to several addresses; one that
blackholes SYNs costs the caller the whole budget and the healthy address is never dialled. A namespace root makes this
worse rather than better, because the name being dialled is a domain name by construction.

**Chosen approach: staggered parallel attempts under one shared budget**, in the shape of RFC 8305 happy eyeballs
without the full algorithm.

1. Resolve the name once with `tokio::net::lookup_host`, inside the budget.
2. Order the addresses by interleaving families, so a broken IPv6 route never delays IPv4 past the first stagger.
3. Start attempt *n* after `attempt_delay` (default 250 ms), leaving earlier attempts running. First connected socket
   wins; the rest are dropped.
4. The caller's `timeout` still bounds the whole thing, and every address gets a real chance inside it.

Rejected: **resolve-then-loop with `timeout / n` per address**, which fixes the bug but still pays seconds for a dead
first address on a four-DC name, and gets worse as the name gets more addresses. Also rejected: dialling all addresses
at once, which puts a SYN on every interface of every server for every connect.

The interface stays additive:

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Budget for the whole attempt, resolution included.
    pub timeout: Duration,
    /// How long to wait before starting the next address. Zero dials all at once.
    pub attempt_delay: Duration,
    /// Cap on how many resolved addresses to try.
    pub max_addresses: usize,
}

impl TcpTransport {
    pub async fn connect(addr: impl ToSocketAddrs, timeout: Duration) -> Result<Self>;      // unchanged signature
    pub async fn connect_with(addr: impl ToSocketAddrs, opts: ConnectOptions) -> Result<Self>;
}
```

`connect` keeps its signature and delegates with `ConnectOptions::default()`, so this is a **behavior change and not an
API break**. `ClientConfig` grows an optional `connect_options: Option<ConnectOptions>` in the same release that adds
its `Default` impl.

When everything fails, `Error::Timeout` says nothing about what was tried. Add:

```rust
/// Every resolved address for a name failed.
#[error("could not connect to {host}: {} address(es) tried", attempts.len())]
ConnectFailed {
    host: String,
    /// One entry per address, in the order they were attempted.
    attempts: Vec<ConnectAttempt>,
},

pub struct ConnectAttempt {
    pub addr: SocketAddr,
    /// `None` when the address ran out of budget rather than failing outright.
    pub error_kind: Option<std::io::ErrorKind>,
}
```

`io::ErrorKind` keeps it a typed enum, so nothing downstream is tempted to match on a message.

**Known limit, documented rather than solved:** `lookup_host` runs `getaddrinfo` on a blocking pool thread. A timeout
abandons the future; the thread stays until the resolver returns. A pure-Rust resolver would fix it and is a dependency
this crate has no other reason to take.

## Testing

The existing fixture `tests/docker/internal/smb-dfs-root/` is the **wrong shape** for this: its `[dfs]` is a real,
tree-connectable share with an `msdfs:` symlink inside, which is the link case the reactive path already covers. It
stays exactly as it is, and keeps covering that.

The 2026-09-16 probe settles the question the plan was most uncertain about: **Samba can serve a namespace root that
refuses TreeConnect**, so the new behavior does not have to live on mocks. Two new containers:

| Container | Port | What it pins |
|---|---|---|
| `smb-dfs-namespace` | 10460 | `msdfs root = yes` + `msdfs proxy = \smb-dfs-target\files`: TreeConnect refused with `STATUS_BAD_NETWORK_NAME`, a V3 root referral over IPC$ |
| `smb-dfs-failover` | 10461 | `msdfs proxy = \nosuchhost\files,\smb-dfs-target\files`: two targets, first unreachable |

Both reuse the existing `smb-dfs-target:10457`, and both reach it through `dfs_target_overrides`, the same way
`dfs_client()` in `tests/docker_integration.rs` already maps `smb-dfs-target` to `127.0.0.1:10457`.

**What the containers prove:** that a TreeConnect refusal triggers a referral; that the referral parses; that the
target connects and reads; that the cache turns the second `connect_share` into one round-trip; that a dead first
target falls through to a live second one; and that a genuinely missing share (referral answers `STATUS_NOT_FOUND`)
comes back as the original `STATUS_BAD_NETWORK_NAME` rather than a DFS error.

**What they cannot prove:** that a Windows DC behaves the same way. Samba answers `ServerType = 0` and
`header_flags = 0x02` where Windows answers `1` and `0x03`, so the fixture is the *stricter* of the two for our
accept-anything reading, and would not catch a regression that started requiring the Windows values. Two mock-transport
tests close that: one feeding a Windows-shaped V4 root referral (`ServerType = 1`, R=1, S=1, `TargetSetBoundary` on the
first entry) and one feeding the Samba-shaped V3 response, both asserting the same resolution. The V4 bytes come from
the existing `resp_parse_v4_referral` test vector, which is a captured Windows response.

**Mock-transport tests** carry everything a container cannot stage: V1 entries; NameListReferral entries; a referral
answering `STATUS_BUFFER_OVERFLOW` then succeeding on retry; `PathConsumed` values that are odd, zero, or longer than
the request; an Interlink response; a referral loop hitting `MAX_DFS_HOPS`; and a target list whose every member
refuses, asserting `DfsNoReachableTarget`.

**Fuzzing:** `fuzz_dfs_referral_response_parse` exists and already caught one V2 bounds bug. V1 and the NameList branch
add two new fixed layouts and one new variable-length list (`NumberOfExpandedNames` strings at `ExpandedNameOffset`,
a server-controlled count), so regenerate the seeds (`just fuzz-seeds`) and run a sweep before release.

**Connect budget:** unit-testable without a network by resolving to a fixed address list. Point one attempt at a
blackholed address (`192.0.2.1`, TEST-NET-1, which drops rather than refuses) and one at a live local listener, and
assert the connection lands well inside the budget. The stagger makes the assertion a real bound rather than a race:
with `attempt_delay = 250 ms` and a 10 s budget, success must arrive in under a second. `smb-flaky:10450` is already
there if an end-to-end version is wanted.

## Steps

Each step is independently committable and green on its own.

1. **Referral wire format.** V1 entries, the NameListReferral branch, `DfsReferralEntry` as a sum type, typed
   `ReferralHeaderFlags` and `ReferralEntryFlags`. Known-bytes tests for each; fuzz seeds regenerated.
2. **Resolver correctness.** Component-aligned and case-preserving matching, `PathConsumed`-derived keys, stored
   `RootOrLink` / `Interlink` / `TargetFailback` / `TargetHint`, bounded cache. Pure unit tests; invert the test that
   currently asserts the lowercasing.
3. **Referral plumbing.** Cached IPC$ tree per connection, `STATUS_BUFFER_OVERFLOW` retry at 64 KiB.
4. **Shared target setup.** Extract `activate_share_encryption`, call it from `ensure_tree`, arm extra connections
   with a reviver, let `recover_tree` handle non-primary trees.
5. **Namespace-root resolution.** Cache-first lookup in `connect_share`, the `CAP_DFS`-gated
   `STATUS_BAD_NETWORK_NAME` trigger, the hop loop, `DfsOrigin`, `Tree` marked `#[non_exhaustive]`,
   `DfsNoReachableTarget` and `DfsTooManyReferrals`.
6. **The two containers**, plus the integration and mock tests above.
7. **Connect budget.** `ConnectOptions`, `connect_with`, staggered attempts, `ConnectFailed`, `ClientConfig::default`
   and its `connect_options` field.
8. **Docs and changelog.** See below.

Steps 1–4 are non-breaking on their own except for `DfsReferralEntry` in step 1. Steps 5 and 7 carry the rest of the
breaking surface, so the whole thing lands as one minor bump.

## Docs to update

- **`AGENTS.md`** § "Spec files": add this plan and `dfs-implementation-plan.md` (which currently has no inbound link
  anywhere in the repo). § "Protocol pitfalls": one new numbered entry for "a namespace root is not a share", carrying
  the `ServerType = 0` trap and the "return the original error" rule, since both span `client/` and `msg/`.
  § "Docker test containers": the two new rows.
- **`crates/smb2/src/client/CLAUDE.md`** § "DFS (Distributed File System) resolution": rewrite for two entry points
  (root at `connect_share`, link at `STATUS_PATH_NOT_COVERED`), the `CAP_DFS` gate, the original-error rule, `TargetHint`,
  and `DfsOrigin`. Link this doc.
- **`crates/smb2/src/msg/CLAUDE.md`**: the NameListReferral branch and the V1 inline-`ShareName` layout beside the
  existing V2 bounds gotcha.
- **`crates/smb2/src/transport/CLAUDE.md`**: `ConnectOptions`, the stagger, and the `getaddrinfo` thread caveat.
- **`crates/smb2/README.md`**: move domain-based DFS out of "Not yet supported" into the feature list; replace it with
  the two honest limitations (no namespace enumeration, no NetBIOS-only domain names). Reword the feature bullet, which
  currently says "standalone DFS".
- **`CHANGELOG.md`**: Breaking (`DfsReferralEntry`, `Tree`), Added (namespace roots, `DfsOrigin`, `ConnectOptions`,
  `ClientConfig::default`), Fixed (case-preserving resolution, component-aligned matching, DFS target encryption,
  buffer overflow, the connect budget).

## Open questions

- **The spec corpus is not checked out.** `AGENTS.md` points at
  `related-repos/openspecs/skills/windows-protocols/MS-*/`, and that tree holds only the upstream repo's `AGENTS.md`
  and `README.md`. The spec text used here came from the `publish` branch of `awakecoding/openspecs`
  (`raw.githubusercontent.com/awakecoding/openspecs/publish/MS-DFSC/MS-DFSC.md`, and the same for MS-SMB2 and
  MS-ERREF). Someone should restore the local corpus or fix the path in `AGENTS.md`; every agent that reads that
  section today finds nothing.
- **No Windows verification.** Everything about Windows behavior here comes from MS-DFSC's own text plus one field log
  from a consumer. The AWS Windows Server 2022 AD DS setup described in `crates/smb2/tests/CLAUDE.md` could host a real
  domain-based namespace and settle it, and is the single highest-value follow-up.
- **The affected environment is not re-testable.** `lgs-net.com` belongs to a Cmdr user. We know the TreeConnect
  status, the negotiated capabilities, and macOS's verdict, and nothing about the referral that machine would return:
  not its version, not its `ServerType`, not how many targets, not whether they are reachable from that client.
- **`STATUS_BAD_NETWORK_NAME` as the sole trigger is a one-server sample.** MS-SMB2 § 3.3.5.7 makes it the required
  status, and Samba agrees, so the ground is firm for Windows and Samba. NetApp, EMC, and other SMB namespace
  implementations are untested. If a second status turns up in the field, it is a one-line addition to the match.
- **Share-redirect collision.** MS-SMB2 § 2.2.2.2.2 uses `STATUS_BAD_NETWORK_NAME` with an
  `SMB2_ERROR_ID_SHARE_REDIRECT` error context for scale-out cluster redirection, an unrelated mechanism the crate does
  not implement. Our trigger never sets `SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER`, so a server should not send it, but
  it is worth an explicit check on the error context before treating the status as DFS.

## Follow-up work, deliberately out of scope

- **Namespace enumeration over MS-DFSNM.** `NetrDfsEnumEx` on the `netdfs` pipe would let a consumer list the
  namespaces a domain hosts and close the "zero shares" gap the field report starts from. It is a new RPC interface on
  top of the existing `rpc/` layer, and it deserves its own plan.
- **Windows AD verification run**, per the open question above.
- **Soft and hard TTLs with a background refresh** (§ 3.1.1), once anything in the crate has a scheduler that wants it.
- **Target failback** (§ 3.1.5.4.3), which needs periodic health checks of a target we moved off.
- **DFS in the batch and pipelined paths**, still excluded as in the original plan.
- **A pure-Rust resolver**, to bound DNS rather than abandon it.
