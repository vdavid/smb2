//! High-level SMB2 client API.
//!
//! Provides [`SmbClient`] for easy connect-and-use access, plus lower-level
//! types: [`Connection`] for message exchange, [`Session`] for authenticated
//! sessions, [`Tree`] for share access with file operations, and [`Pipeline`]
//! for batched concurrent operations.

pub mod connection;
pub mod copy;
pub(crate) mod credits;
pub(crate) mod dfs;
pub mod diagnostics;
pub mod durable;
#[cfg(test)]
mod fault_injection_tests;
pub mod pipeline;
pub mod session;
pub mod shares;
pub mod stream;
#[cfg(test)]
pub(crate) mod test_helpers;
pub mod tree;
pub mod watcher;

pub use crate::crypto::encryption::Cipher;
pub use connection::{
    CompoundOp, Connection, Frame, NegotiatedParams, ReconnectEvent, ReconnectObserver,
    ReconnectPolicy, SessionReviver,
};
pub use diagnostics::{
    ClientInfo, ClientMetricsSnapshot, CompressionInfo, ConnectionDiagnostics, CreditInfo,
    DfsCacheEntry, Diagnostics, EncryptionInfo, MetricsSnapshot, NegotiatedSummary,
    SessionDiagnostics, SigningInfo,
};
pub use durable::{DurableHandle, DurableOpen};
pub use pipeline::{Op, OpResult, Pipeline};
pub use session::Session;
pub use shares::list_shares;
pub use stream::{FileDownload, FileUpload, FileWriter, Progress};
pub use tree::{DfsOrigin, DirectoryEntry, FileInfo, FsInfo, ListingTrace, QueryStep, Tree};
pub use watcher::{FileNotifyAction, FileNotifyEvent, Watcher};

// Re-export high-level client types.
// (SmbClient, ClientConfig, and connect are defined below in this file.)

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use log::{debug, info, trace};

use crate::client::dfs::DfsResolver;
use crate::error::{ErrorKind, Result};
use crate::pack::Unpack;
use crate::rpc::srvsvc::ShareInfo;
use crate::types::status::NtStatus;
use crate::types::FileId;
use crate::Error;

/// Configuration for an SMB client connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server address (host:port).
    pub addr: String,
    /// Connection timeout.
    pub timeout: Duration,
    /// Username (empty for guest).
    pub username: String,
    /// Password (empty for guest).
    ///
    /// **Security note:** The password is stored in memory so that the client
    /// can reconnect without asking the user again. It is not encrypted in
    /// memory. Ensure the `SmbClient` is dropped when no longer needed.
    pub password: String,
    /// Domain (empty for local).
    pub domain: String,
    /// Bring the connection back by itself when the session dies.
    ///
    /// With this on, [`SmbClient::connect`] arms the connection with a
    /// [`SessionReviver`] built from this config, so a dead session (a NAS
    /// rebooting, a Wi-Fi roam with no TCP reset, a share going briefly
    /// offline) is re-dialed, re-negotiated, and re-authenticated in place
    /// under every `Connection` clone the consumer is holding. Bounds live in
    /// [`ReconnectPolicy`]; nothing here can retry forever.
    ///
    /// **What it does NOT do is re-issue arbitrary work.** Only operations
    /// whose retry cannot change what the caller asked for are replayed
    /// (directory listings, reads, `stat`, `fs_info`). A `delete`, `rename`,
    /// or `create` that died in flight may already have taken effect on the
    /// server, so it surfaces the error and lets the caller decide — hiding
    /// that would be the library guessing about the user's data.
    ///
    /// **Security note:** the reviver keeps a copy of
    /// [`password`](Self::password) for the life of the client, for the same
    /// reason this struct does.
    pub auto_reconnect: bool,
    /// Enable LZ4 compression for SMB 3.1.1 connections.
    /// When enabled, messages are compressed if it reduces their size.
    /// Incompressible data (photos, videos) is sent uncompressed automatically.
    /// Default: true.
    pub compression: bool,
    /// Enable DFS (Distributed File System) path resolution.
    ///
    /// When `true`, operations that receive a DFS referral response
    /// (`STATUS_PATH_NOT_COVERED`) automatically resolve the referral,
    /// connect to the target server, and retry the operation.
    /// Default: true.
    pub dfs_enabled: bool,
    /// Override addresses for DFS target servers.
    ///
    /// Maps server hostnames (as they appear in DFS referrals) to
    /// `host:port` socket addresses. Useful when DFS targets use
    /// internal hostnames that the client can't resolve, or when
    /// port mapping is needed (for example, Docker test environments).
    ///
    /// Default: empty (use the server hostname from the referral
    /// with port 445).
    pub dfs_target_overrides: std::collections::HashMap<String, String>,
    /// How the TCP connect is spread across the addresses
    /// [`addr`](Self::addr) resolves to.
    ///
    /// `None` uses [`ConnectOptions::with_timeout`](crate::transport::ConnectOptions::with_timeout) with
    /// [`timeout`](Self::timeout), which is what you want unless you are
    /// tuning for a name with an unusual number of addresses. See
    /// [`ConnectOptions`](crate::transport::ConnectOptions) for why a single deadline around
    /// `TcpStream::connect` is not enough.
    pub connect_options: Option<crate::transport::ConnectOptions>,
}

impl ClientConfig {
    /// The connect budget this config asks for: its own
    /// [`connect_options`](Self::connect_options), or the defaults with
    /// [`timeout`](Self::timeout) as the whole-attempt budget.
    pub(crate) fn connect_options(&self) -> crate::transport::ConnectOptions {
        self.connect_options
            .clone()
            .unwrap_or_else(|| crate::transport::ConnectOptions::with_timeout(self.timeout))
    }
}

impl Default for ClientConfig {
    /// Guest access to nothing, with compression and DFS on.
    ///
    /// Exists so a field added here is not a breaking change for every caller
    /// writing a struct literal, which is all of them: fill in
    /// [`addr`](Self::addr) and whatever else you need, and spread the rest.
    ///
    /// ```
    /// # use smb2::ClientConfig;
    /// let config = ClientConfig {
    ///     addr: "nas.local:445".to_string(),
    ///     username: "david".to_string(),
    ///     auto_reconnect: true,
    ///     ..Default::default()
    /// };
    /// ```
    fn default() -> Self {
        Self {
            addr: String::new(),
            timeout: Duration::from_secs(5),
            username: String::new(),
            password: String::new(),
            domain: String::new(),
            auto_reconnect: false,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: std::collections::HashMap::new(),
            connect_options: None,
        }
    }
}

/// Dials and re-authenticates on a consumer's behalf when a session dies.
///
/// Holds a snapshot of the client's config rather than a back-reference to the
/// [`SmbClient`], so a revival can run from any `Connection` clone (a
/// `FileWriter` deep in a transfer, a `Watcher` on its own task) without
/// reaching back through a client nobody has a handle to.
///
/// **Security note:** it keeps the password for the life of the client, which
/// is the same trade [`SmbClient`] already makes to reconnect without
/// re-prompting.
struct ClientReviver {
    addr: String,
    connect_options: crate::transport::ConnectOptions,
    compression: bool,
    username: String,
    password: String,
    domain: String,
}

impl ClientReviver {
    fn from_config(config: &ClientConfig) -> Self {
        Self::for_addr(config, config.addr.clone())
    }

    /// A reviver for a server other than the one the client was built for.
    ///
    /// A DFS target lives at its own address with its own session, so it needs
    /// its own reviver; `config.addr` would dial the namespace server back.
    /// Everything else (credentials, timeout, compression) is the client's.
    fn for_addr(config: &ClientConfig, addr: String) -> Self {
        Self {
            addr,
            connect_options: config.connect_options(),
            compression: config.compression,
            username: config.username.clone(),
            password: config.password.clone(),
            domain: config.domain.clone(),
        }
    }
}

#[async_trait::async_trait]
impl connection::SessionReviver for ClientReviver {
    async fn dial(
        &self,
    ) -> Result<(
        Box<dyn crate::transport::TransportSend>,
        Box<dyn crate::transport::TransportReceive>,
    )> {
        let transport = std::sync::Arc::new(
            crate::transport::TcpTransport::connect_with(&self.addr, self.connect_options.clone())
                .await?,
        );
        Ok((
            Box::new(std::sync::Arc::clone(&transport)),
            Box::new(transport),
        ))
    }

    async fn reauthenticate(&self, conn: &mut Connection) -> Result<()> {
        conn.set_compression_requested(self.compression);
        conn.negotiate().await?;
        // `Session::setup` publishes the new session onto the connection, so
        // an `SmbClient` that has one cached picks the new keys up.
        Session::setup(conn, &self.username, &self.password, &self.domain).await?;
        Ok(())
    }
}

/// Turn on encryption for a share that asked for it
/// (`SMB2_SHAREFLAG_ENCRYPT_DATA`), if it is not on already.
///
/// ❌ **Every tree connect goes through here.** A share that asked to be
/// encrypted and is not is a data-confidentiality bug, not a convenience gap,
/// and a DFS target share is exactly as entitled to it as the one the caller
/// named. Falls back to AES-128-CCM when the server sent no encryption
/// negotiate context, the same fallback session-level encryption makes.
fn activate_share_encryption(conn: &mut Connection, session: &Session, tree: &Tree) {
    if !tree.encrypt_data || conn.should_encrypt() {
        return;
    }
    let (Some(enc_key), Some(dec_key)) = (&session.encryption_key, &session.decryption_key) else {
        return;
    };
    let cipher = conn
        .params()
        .and_then(|p| p.cipher)
        .unwrap_or(crate::crypto::encryption::Cipher::Aes128Ccm);
    conn.activate_encryption(enc_key.clone(), dec_key.clone(), cipher);
}

/// How many referrals one connect may follow before we call it a loop.
///
/// A real namespace resolves in one hop, and an Interlink (MS-DFSC
/// § 3.1.5.4.5) adds one more. Anything near this limit is a namespace
/// pointing at itself or a chain with no end, which is a misconfiguration on
/// the server: a knob here would only let a consumer wait longer for the same
/// answer.
const MAX_DFS_HOPS: usize = 8;

/// The host half of a `host:port` address, for the places that need a NAME
/// rather than something to dial: the UNC path in every `TREE_CONNECT` and the
/// DFS referral cache key.
///
/// ❌ Never `split(':')`. That reads `[::1]:445` as `[` and `fe80::1:445` as
/// `fe80`, and the wrong name then goes out as the server half of the UNC path.
/// Two sites derived this separately and disagreed, which on a DFS share means
/// the cache key and the tree-connect path name different servers.
///
/// **Matches what `ToSocketAddrs` will actually dial**, which is the whole
/// point of deriving it here rather than guessing: std splits a bracket-less
/// address on the LAST colon, so `fe80::1:445` is host `fe80::1` on port 445
/// even though the same text is also a valid IPv6 address in its own right.
/// A bracket-less literal with no port is genuinely ambiguous and is read as
/// carrying a port, exactly as std reads it; one cannot reach here anyway,
/// since `lookup_host` refuses a portless address ("invalid port value") and
/// the client is never built.
pub(crate) fn host_of(addr: &str) -> &str {
    // A bracketed literal says where it ends, which is what brackets are for.
    if let Some(host) = addr
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(host, _)| host)
    {
        return host;
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        _ => addr,
    }
}

/// One `Error::Disconnected` per item, for a batch method that never found a
/// connection to run on.
///
/// `Error` is not `Clone` (it can carry a boxed source), so each item gets its
/// own. The batch methods report per item and have no other way to say this.
fn no_connection_results<T>(len: usize) -> Vec<Result<T>> {
    (0..len).map(|_| Err(Error::Disconnected)).collect()
}

/// A connection to a specific server with its authenticated session.
///
/// Used for DFS cross-server referrals where the client needs connections
/// to multiple servers simultaneously.
#[allow(dead_code)]
pub(crate) struct ConnectionEntry {
    /// The connection to the server.
    pub conn: Connection,
    /// The session as of the last authentication on this connection. Behind
    /// an `Arc` for the same reason the primary's is: a revival can establish
    /// a new one behind this client's back, and share encryption derives from
    /// the live keys.
    pub session: std::sync::Arc<Session>,
}

/// High-level SMB2 client with reconnection support.
///
/// Wraps a [`Connection`] + [`Session`] and provides methods for connecting
/// to shares, listing shares, and reconnecting after network failures.
///
/// **Security note:** This struct stores the password in memory so it can
/// reconnect without asking the user again. The password is not encrypted.
/// Drop the `SmbClient` when no longer needed.
pub struct SmbClient {
    config: ClientConfig,
    conn: Connection,
    /// The session as of the last authentication. Behind an `Arc` because a
    /// revival can establish a new one behind this client's back; every
    /// `&mut self` path that reads the session keys refreshes it first.
    session: std::sync::Arc<Session>,
    /// Server name of the primary connection (from `conn.server_name()`).
    primary_server: String,
    /// Extra connections for DFS cross-server targets, keyed by server name.
    extra_connections: HashMap<String, ConnectionEntry>,
    /// DFS referral resolver with TTL-based cache.
    dfs_resolver: DfsResolver,
    /// Client-level counter: how many times `reconnect()` ran. Survives
    /// each reconnect (per-connection counters do not).
    reconnects: AtomicU64,
}

impl SmbClient {
    /// Connect to an SMB server and authenticate.
    ///
    /// Performs TCP connect, negotiate, and session setup in one call.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        debug!("smb_client: connecting to {}", config.addr);

        let mut conn = Connection::connect_with(&config.addr, config.connect_options()).await?;
        conn.set_compression_requested(config.compression);
        conn.negotiate().await?;

        let session = Session::setup(
            &mut conn,
            &config.username,
            &config.password,
            &config.domain,
        )
        .await?;

        debug!(
            "smb_client: connected and authenticated, session_id={}, compression={}",
            session.session_id,
            conn.compression_enabled()
        );

        let primary_server = config.addr.clone();
        if config.auto_reconnect {
            conn.set_reviver(Some(std::sync::Arc::new(ClientReviver::from_config(
                &config,
            ))));
        }

        Ok(SmbClient {
            config,
            conn,
            session: std::sync::Arc::new(session),
            primary_server,
            extra_connections: HashMap::new(),
            dfs_resolver: DfsResolver::new(),
            reconnects: AtomicU64::new(0),
        })
    }

    /// Connect using an existing connection and session (for testing).
    #[cfg(test)]
    pub(crate) fn from_parts(config: ClientConfig, conn: Connection, session: Session) -> Self {
        let primary_server = config.addr.clone();
        SmbClient {
            config,
            conn,
            session: std::sync::Arc::new(session),
            primary_server,
            extra_connections: HashMap::new(),
            dfs_resolver: DfsResolver::new(),
            reconnects: AtomicU64::new(0),
        }
    }

    /// Adopt a session established on the connection behind this client's
    /// back, which is what a revival does.
    ///
    /// ❌ Skipping this is not cosmetic: [`connect_share`](Self::connect_share)
    /// activates share encryption from these keys, and the previous session's
    /// keys decrypt nothing — every frame afterwards fails.
    fn refresh_session(&mut self) {
        if let Some(current) = self.conn.current_session() {
            if current.session_id != self.session.session_id {
                debug!(
                    "smb_client: adopting session {} established by a reconnect \
                     (was {})",
                    current.session_id, self.session.session_id
                );
                self.session = current;
            }
        }
    }

    /// List available shares on the server.
    ///
    /// Connects to the IPC$ share, performs an RPC exchange via the srvsvc
    /// named pipe, and returns only disk shares (excluding admin shares
    /// ending with `$`).
    pub async fn list_shares(&mut self) -> Result<Vec<ShareInfo>> {
        shares::list_shares(&mut self.conn).await
    }

    /// Connect to a share on the server.
    ///
    /// If the share requires encryption (`SMB2_SHAREFLAG_ENCRYPT_DATA`)
    /// and encryption is not already active, encryption is activated
    /// using the session's keys.
    ///
    /// # DFS namespace roots
    ///
    /// `share_name` may be a **DFS namespace** rather than a share on this
    /// server — `\\lgs-net.com\aleu`, where `lgs-net.com` is a domain name and
    /// `aleu` is the namespace. There is no such share to tree-connect, so the
    /// server refuses with `STATUS_BAD_NETWORK_NAME`; this method then asks it
    /// for a root referral and connects the target the referral names, on
    /// whichever server that turns out to be. The returned `Tree` carries a
    /// [`DfsOrigin`] recording both names, so a consumer can keep showing the
    /// path the person asked for.
    ///
    /// A cached namespace skips straight to the target, so the wasted
    /// `TREE_CONNECT` is paid once per TTL rather than once per connect.
    ///
    /// **A mistyped share name is still a mistyped share name.** The referral
    /// only happens when the server advertised `SMB2_GLOBAL_CAP_DFS`, and if
    /// it fails, comes back empty, or names nothing reachable-looking, the
    /// caller gets the original `STATUS_BAD_NETWORK_NAME` back rather than
    /// something about DFS. The one case that reports differently is a real
    /// namespace whose storage is all down:
    /// [`Error::DfsNoReachableTarget`].
    pub async fn connect_share(&mut self, share_name: &str) -> Result<Tree> {
        self.refresh_session();

        // § 3.1.4.1 step 2: the cache first, so a known namespace never pays
        // the refused TreeConnect again inside its TTL. Terminal on purpose —
        // falling back to a plain tree connect afterwards would resolve the
        // namespace twice and double the wait on the one path where the wait
        // is long (every target down). An entry whose TTL has run out reports
        // a miss, so a namespace that has genuinely become an ordinary share
        // is found again then.
        let requested = self.unc_for(share_name);
        if self.config.dfs_enabled && self.dfs_resolver.resolve_from_cache(&requested).is_some() {
            trace!("dfs: {requested:?} is a known namespace, going straight to its targets");
            return self.connect_namespace(&requested).await;
        }

        // § 3.1.4.1 step 8 for the ordinary world: tree-connect, and on
        // success we are done at zero extra cost.
        let refusal = match Tree::connect(&mut self.conn, share_name).await {
            Ok(mut tree) => {
                tree.server = self.primary_server.clone();
                activate_share_encryption(&mut self.conn, &self.session, &tree);
                return Ok(tree);
            }
            Err(err) => err,
        };

        if !self.looks_like_a_namespace_root(&refusal) {
            return Err(refusal);
        }

        debug!(
            "dfs: {share_name:?} is not a share on {}, and the server speaks DFS; \
             asking it for a root referral",
            self.primary_server
        );
        match self.connect_namespace(&requested).await {
            Ok(tree) => Ok(tree),
            // ❌ A failed referral must not replace the original error. The
            // overwhelmingly common reason for STATUS_BAD_NETWORK_NAME is a
            // typo in a share name, and telling that person about DFS is
            // worse than telling them nothing. Only the one outcome that is
            // genuinely about DFS survives.
            Err(err @ (Error::DfsNoReachableTarget { .. } | Error::DfsTooManyReferrals { .. })) => {
                Err(err)
            }
            Err(err) => {
                debug!("dfs: no namespace behind {share_name:?} ({err}); reporting the refusal");
                Err(refusal)
            }
        }
    }

    /// The UNC path for a share on the primary server, as a referral names it.
    fn unc_for(&self, share_name: &str) -> String {
        format!(r"\\{}\{}", host_of(&self.primary_server), share_name)
    }

    /// Whether a refused `TREE_CONNECT` might be a DFS namespace root rather
    /// than a share that is simply not there.
    ///
    /// MS-SMB2 § 3.3.5.7 makes `STATUS_BAD_NETWORK_NAME` the required answer
    /// for a name the server has no share for, which is what a namespace root
    /// is from the server's point of view. Gating on the negotiated
    /// `SMB2_GLOBAL_CAP_DFS` keeps a plain NAS at zero extra round-trips when
    /// someone mistypes a share name; a server that does advertise DFS pays
    /// one extra frame on an error path.
    ///
    /// `Error::ShareRedirected` deliberately does not reach here:
    /// `Tree::connect` separates cluster redirection out, and it shares only
    /// the status code with this.
    fn looks_like_a_namespace_root(&self, err: &Error) -> bool {
        self.config.dfs_enabled
            && matches!(
                err,
                Error::Protocol {
                    status: NtStatus::BAD_NETWORK_NAME,
                    command: crate::types::Command::TreeConnect,
                }
            )
            && self.conn.params().is_some_and(|p| {
                p.capabilities
                    .contains(crate::types::flags::Capabilities::DFS)
            })
    }

    /// Resolve `requested` as a DFS namespace and connect the first target
    /// that answers.
    ///
    /// Follows Interlinks (MS-DFSC § 3.1.5.4.5: the target is a path in
    /// another namespace, so it is re-resolved rather than connected) up to
    /// [`MAX_DFS_HOPS`], which is what stops a namespace that points at
    /// itself from resolving forever.
    async fn connect_namespace(&mut self, requested: &str) -> Result<Tree> {
        let mut path = requested.to_string();

        for _ in 0..MAX_DFS_HOPS {
            let targets = self.root_referral(&path).await?;

            // The chain ended without naming anywhere to go. ❌ This has to
            // leave by its own exit: sharing one with the hop limit below
            // means telling the caller we exhausted eight hops when the chain
            // simply ran out after two. `DfsResolver::resolve` reports an
            // error rather than an empty list today, so this is a guard on its
            // contract rather than a path anything takes.
            if targets.is_empty() {
                return Err(Error::invalid_data(if path == requested {
                    format!("DFS referral for {requested} named no targets")
                } else {
                    format!(
                        "DFS referral for {requested} followed an interlink to {path}, \
                         which named no targets"
                    )
                }));
            }

            // An Interlink means the whole response is a path in another
            // namespace, so there is nothing here to connect to.
            if let Some(first) = targets.first().filter(|t| t.interlink) {
                path = format!(r"\\{}\{}", first.server, first.share);
                trace!("dfs: {requested:?} is an interlink, re-resolving as {path:?}");
                continue;
            }

            // Past here the hop is decided: every exit below returns, so
            // nothing after the loop has to work out how we got there.
            let target_count = targets.len();
            let mut last_error: Option<Error> = None;

            for target in &targets {
                // A root target is `\\server\share` and nothing more
                // (MS-DFSC § 2.2.1.6). A `Tree` cannot express a path suffix,
                // so a target carrying one is skipped rather than silently
                // dropping the suffix and opening the wrong directory.
                if !target.remaining_path.is_empty() {
                    debug!(
                        "dfs: skipping target \\\\{}\\{} for {requested:?}: a root target \
                         cannot carry the path suffix {:?}",
                        target.server, target.share, target.remaining_path
                    );
                    continue;
                }

                let target_addr = self.target_addr(target);
                match self.connect_target(&target_addr, &target.share).await {
                    Ok(mut tree) => {
                        self.dfs_resolver.note_target_worked(target);
                        tree.dfs_origin = Some(DfsOrigin {
                            requested: requested.to_string(),
                            target: format!(r"\\{}\{}", target.server, target.share),
                        });
                        info!(
                            "dfs: namespace {requested} resolved to \\\\{}\\{}",
                            target.server, target.share
                        );
                        return Ok(tree);
                    }
                    Err(err) => {
                        debug!("dfs: target {target_addr} for {requested:?} refused: {err}");
                        last_error = Some(err);
                    }
                }
            }

            return match last_error {
                Some(source) => Err(Error::DfsNoReachableTarget {
                    namespace: requested.to_string(),
                    target_count,
                    source: Box::new(source),
                }),
                // Every target was skipped as unusable rather than failing,
                // so there is no connectivity story to tell.
                None => Err(Error::invalid_data(format!(
                    "DFS referral for {requested} named {target_count} target(s), \
                     none of them a share this client can connect to"
                ))),
            };
        }

        // The only way out of that loop is the Interlink `continue`, once per
        // hop, so reaching here means exactly that and nothing else.
        Err(Error::DfsTooManyReferrals {
            namespace: requested.to_string(),
            hops: MAX_DFS_HOPS,
        })
    }

    /// Ask the server that owns `path` for a referral, resolving from cache
    /// when it is already known.
    async fn root_referral(&mut self, path: &str) -> Result<Vec<dfs::ResolvedPath>> {
        // The referral goes to the server naming the path, which after an
        // Interlink is not the one the caller started on.
        let host = path.trim_start_matches('\\');
        let host = host.split('\\').next().unwrap_or(host);
        let addr = self.dfs_addr_for_host(host);

        if addr != self.primary_server {
            self.ensure_connection(&addr).await?;
        }
        // Inlined rather than `connection_for_tree`, so `self.dfs_resolver`
        // and the connection aren't borrowed from `self` at the same time.
        let conn = if addr == self.primary_server {
            &mut self.conn
        } else {
            &mut self
                .extra_connections
                .get_mut(&addr)
                .ok_or(Error::Disconnected)?
                .conn
        };
        self.dfs_resolver.resolve(conn, path).await
    }

    /// Where to actually dial for a referral target, honouring
    /// [`ClientConfig::dfs_target_overrides`].
    fn target_addr(&self, target: &dfs::ResolvedPath) -> String {
        self.config
            .dfs_target_overrides
            .get(&target.server)
            .cloned()
            .unwrap_or_else(|| format!("{}:{}", target.server, target.port))
    }

    /// The same mapping for a bare host name, which is what an Interlink
    /// hands back.
    fn dfs_addr_for_host(&self, host: &str) -> String {
        self.config
            .dfs_target_overrides
            .get(host)
            .cloned()
            .unwrap_or_else(|| {
                if host == self.primary_server
                    || self.primary_server.starts_with(&format!("{host}:"))
                {
                    self.primary_server.clone()
                } else {
                    format!("{host}:445")
                }
            })
    }

    /// Connect (pooling the connection) and tree-connect one referral target.
    async fn connect_target(&mut self, target_addr: &str, share: &str) -> Result<Tree> {
        self.ensure_connection(target_addr).await?;
        self.ensure_tree(target_addr, share).await
    }

    /// Reconnect now, whether or not the connection has noticed it is dead.
    ///
    /// Dials a fresh socket, renegotiates, and re-authenticates with the
    /// stored credentials, **in place under the existing connection**: every
    /// `Connection` clone the consumer is holding (a `FileWriter` mid-upload,
    /// a `Watcher`, a pipelined task) stays usable. All previous tree
    /// connections and file handles are invalidated regardless — they belong
    /// to a session that no longer exists — so the caller must re-do
    /// [`connect_share`](Self::connect_share) for any shares it still needs.
    ///
    /// Bounded by [`ReconnectPolicy`]; on failure the
    /// connection is left unambiguously dead and the error is
    /// [`Error::ReconnectFailed`].
    pub async fn reconnect(&mut self) -> Result<()> {
        debug!("smb_client: reconnecting to {}", self.config.addr);
        self.reconnects.fetch_add(1, Ordering::Relaxed);

        // An explicit reconnect works even when `auto_reconnect` is off: the
        // caller is asking for exactly this, and everything needed to do it is
        // already in the config.
        if !self.conn.can_reconnect() {
            self.conn
                .set_reviver(Some(std::sync::Arc::new(ClientReviver::from_config(
                    &self.config,
                ))));
        }
        // Say so first: `reconnect_if_needed` is a no-op on a connection that
        // still looks alive, and a caller reaching for this has decided
        // otherwise.
        self.conn.mark_dead();
        self.conn.reconnect_if_needed().await?;
        self.refresh_session();

        self.primary_server = self.config.addr.clone();
        self.extra_connections.clear();

        debug!(
            "smb_client: reconnected, new session_id={}",
            self.session.session_id
        );
        Ok(())
    }

    /// Whether the connection is currently torn down.
    pub fn is_disconnected(&self) -> bool {
        self.conn.is_disconnected()
    }

    /// Be told about every reconnect as it happens. See
    /// [`Connection::on_reconnect`].
    pub fn on_reconnect(&self, observer: Option<connection::ReconnectObserver>) {
        self.conn.on_reconnect(observer);
    }

    /// Replace the bounds on an automatic reconnect. See
    /// [`ReconnectPolicy`].
    pub fn set_reconnect_policy(&self, policy: connection::ReconnectPolicy) {
        self.conn.set_reconnect_policy(policy);
    }

    /// Get the negotiated parameters, or `None` before NEGOTIATE has run.
    ///
    /// Owned rather than borrowed: the parameters are replaced whenever the
    /// connection is revived on a fresh socket. Every field is a scalar, so
    /// the copy costs nothing.
    pub fn params(&self) -> Option<NegotiatedParams> {
        self.conn.params()
    }

    /// Get the session info.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get the client config.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Current number of available credits.
    pub fn credits(&self) -> u16 {
        self.conn.credits()
    }

    /// Estimated round-trip time from the negotiate exchange.
    pub fn estimated_rtt(&self) -> Option<Duration> {
        self.conn.estimated_rtt()
    }

    /// Capture a tree of diagnostics: client config, primary + DFS-extra
    /// connections, the session on each connection, per-connection
    /// counters, the DFS referral cache, and client-level counters.
    ///
    /// See [`crate::client::diagnostics`] for the consistency model. In
    /// short: eventually consistent, snapshot survives connection
    /// teardown, per-connection counters reset on
    /// [`Self::reconnect`], client-level counters survive.
    pub fn diagnostics(&self) -> crate::client::diagnostics::Diagnostics {
        use crate::client::diagnostics::{
            ClientInfo, ClientMetricsSnapshot, Diagnostics, SessionDiagnostics,
        };

        let (cache_hits, referrals_resolved) = self.dfs_resolver.counters();
        let client = ClientInfo {
            primary_server: self.primary_server.clone(),
            timeout: self.config.timeout,
            auto_reconnect: self.config.auto_reconnect,
            dfs_enabled: self.config.dfs_enabled,
            metrics: ClientMetricsSnapshot {
                reconnects: self.reconnects.load(Ordering::Relaxed),
                dfs_referrals_resolved: referrals_resolved,
                dfs_cache_hits: cache_hits,
            },
        };

        let session_for = |s: &Session| SessionDiagnostics {
            session_id: s.session_id,
            should_sign: s.should_sign,
            should_encrypt: s.should_encrypt,
            signing_algorithm: s.signing_algorithm,
        };

        let mut primary = self.conn.diagnostics();
        primary.session = Some(session_for(&self.session));

        let extra_connections = self
            .extra_connections
            .values()
            .map(|entry| {
                let mut d = entry.conn.diagnostics();
                d.session = Some(session_for(&entry.session));
                d
            })
            .collect();

        Diagnostics {
            client,
            primary,
            extra_connections,
            dfs_cache: self.dfs_resolver.cache_entries(),
        }
    }

    /// Get a mutable reference to the underlying connection.
    ///
    /// Needed when using [`Tree`] methods directly, since they require
    /// `&mut Connection`. For most use cases, prefer the convenience methods
    /// on `SmbClient` (like [`list_directory`](Self::list_directory)) instead.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Get a mutable reference to the connection that owns the given tree.
    ///
    /// Routes through the primary connection when the tree's server matches,
    /// or through an extra connection established for a DFS cross-server
    /// referral.
    ///
    /// ❌ **Not a panic.** A `Tree` outlives the pool entry it was resolved
    /// on: [`reconnect`](Self::reconnect) drops every extra connection, and a
    /// consumer reasonably still holds the DFS-resolved `Tree` it had. That
    /// used to panic inside a library. `Error::Disconnected` is both true and
    /// the classification whose documented response —
    /// [`connect_share`](Self::connect_share) again — is exactly right here.
    pub(crate) fn connection_for_tree(&mut self, tree: &Tree) -> Result<&mut Connection> {
        if tree.server == self.primary_server {
            return Ok(&mut self.conn);
        }
        match self.extra_connections.get_mut(&tree.server) {
            Some(entry) => Ok(&mut entry.conn),
            None => {
                debug!(
                    "smb_client: no connection for {} (share {:?}); the DFS target it was \
                     resolved on is gone, so connect_share again",
                    tree.server, tree.share_name
                );
                Err(Error::Disconnected)
            }
        }
    }

    // ── DFS helpers ───────────────────────────────────────────────────

    /// Handle a DFS redirect by resolving the referral, connecting to
    /// the target server (creating a new connection if needed), and
    /// updating the tree in-place.
    ///
    /// Returns the resolved remaining path to use for the retry.
    async fn handle_dfs_redirect(
        &mut self,
        tree: &mut Tree,
        original_path: &str,
    ) -> Result<String> {
        // The referral lookup and the tree-connect path have to name the same
        // server, so this goes through the one derivation (`host_of`).
        let hostname = host_of(&tree.server).to_string();
        let share = tree.share_name.clone();
        // Encoded, not just slash-flipped: the referral lookup and the CREATE
        // that follows have to agree on where a component ends, and a `\` that
        // came from a *name* is U+F026 in both (`crate::name`).
        let normalized = crate::name::encode_path(original_path);
        let unc_path = format!("\\\\{}\\{}\\{}", hostname, share, normalized);

        debug!("dfs: resolving {}", unc_path);

        // Resolve the referral (uses cache or IOCTL).
        // We inline the connection lookup to avoid borrowing both
        // `self.dfs_resolver` and `self` (via connection_for_tree)
        // at the same time.
        let conn = if tree.server == self.primary_server {
            &mut self.conn
        } else {
            &mut self
                .extra_connections
                .get_mut(&tree.server)
                .expect("no connection for tree server")
                .conn
        };
        let resolved_list = self.dfs_resolver.resolve(conn, &unc_path).await?;

        // Try each target (multi-target failover).
        let mut last_error = None;
        for resolved in &resolved_list {
            let target_addr = self
                .config
                .dfs_target_overrides
                .get(&resolved.server)
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", resolved.server, resolved.port));

            // Get or create connection to target server.
            match self.ensure_connection(&target_addr).await {
                Ok(()) => {}
                Err(e) => {
                    debug!("dfs: failed to connect to {}: {}", target_addr, e);
                    last_error = Some(e);
                    continue;
                }
            }

            // Get or create tree on the target share.
            match self.ensure_tree(&target_addr, &resolved.share).await {
                Ok(new_tree) => {
                    // Remember which target worked, so a failover survives
                    // the next lookup instead of re-walking the dead one.
                    self.dfs_resolver.note_target_worked(resolved);
                    // Update the caller's tree in-place.
                    *tree = new_tree;
                    // Back into caller-path form: the retry goes through the
                    // ordinary `Tree` methods, which encode what they're given.
                    return Ok(crate::name::decode_path(&resolved.remaining_path));
                }
                Err(e) => {
                    debug!(
                        "dfs: failed to connect to share {} on {}: {}",
                        resolved.share, target_addr, e
                    );
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::invalid_data("DFS: no targets in referral")))
    }

    /// Ensure a connection exists in the pool for the given server address.
    async fn ensure_connection(&mut self, target_addr: &str) -> Result<()> {
        if target_addr == self.primary_server {
            return Ok(()); // Already have primary connection.
        }
        if self.extra_connections.contains_key(target_addr) {
            return Ok(()); // Already in pool.
        }

        // Create new connection to target.
        let mut conn = Connection::connect_with(target_addr, self.config.connect_options()).await?;
        conn.set_compression_requested(self.config.compression);
        conn.negotiate().await?;

        // Authenticate with same credentials.
        let session = Session::setup(
            &mut conn,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
        )
        .await?;

        // Arm it the same way the primary is. On a namespace root the target
        // connection carries *all* of the user's traffic, so leaving it
        // unrevivable meant `auto_reconnect` silently did not cover the only
        // connection that mattered. The reviver is built for this address, not
        // `config.addr`, which would dial the namespace server back.
        if self.config.auto_reconnect {
            conn.set_reviver(Some(std::sync::Arc::new(ClientReviver::for_addr(
                &self.config,
                target_addr.to_string(),
            ))));
        }
        // And it inherits the bounds the consumer set on the primary, rather
        // than silently falling back to the defaults.
        conn.set_reconnect_policy(self.conn.reconnect_policy());

        self.extra_connections.insert(
            target_addr.to_string(),
            ConnectionEntry {
                conn,
                session: std::sync::Arc::new(session),
            },
        );
        Ok(())
    }

    /// Ensure a tree-connect exists for the given server and share.
    async fn ensure_tree(&mut self, target_addr: &str, share: &str) -> Result<Tree> {
        // `tree.server` is the full addr:port, so `connection_for_tree` can
        // tell apart targets sharing a hostname on different ports (Docker
        // port-mapped containers, for one).
        //
        // Two branches rather than one, because the primary connection's
        // session lives beside it on `self` while an extra connection carries
        // its own, authenticated separately.
        if target_addr == self.primary_server {
            self.refresh_session();
            let mut tree = Tree::connect(&mut self.conn, share).await?;
            tree.server = target_addr.to_string();
            activate_share_encryption(&mut self.conn, &self.session, &tree);
            return Ok(tree);
        }

        let entry = self
            .extra_connections
            .get_mut(target_addr)
            .ok_or_else(|| Error::invalid_data("DFS: no connection for target"))?;
        let mut tree = Tree::connect(&mut entry.conn, share).await?;
        tree.server = target_addr.to_string();
        activate_share_encryption(&mut entry.conn, &entry.session, &tree);
        Ok(tree)
    }

    /// Check whether a DFS retry should be attempted for the given error.
    fn should_retry_dfs(&self, err: &Error) -> bool {
        self.config.dfs_enabled && err.kind() == ErrorKind::DfsReferral
    }

    /// Whether this failure means "the session is gone" and auto-reconnect is
    /// armed to do something about it.
    ///
    /// Deliberately narrow. [`Error::CreditStarvation`], [`Error::SendTimeout`]
    /// and a plain [`Error::Timeout`] also smell like a dead link, but none of
    /// them proves the session died, and re-running an operation against a
    /// connection that is merely struggling buys a duplicate request rather
    /// than a recovery. These two are the ones that mean it: `Disconnected`
    /// says the socket went away, and `ServerUnresponsive` is only reached
    /// when a request burned its whole deadline on a connection that put
    /// nothing at all on the wire — and it leaves the connection marked dead,
    /// which is what gives `reconnect_if_needed` something to revive.
    /// Asked of the connection the tree actually lives on, which for a DFS
    /// target is not the primary one.
    fn session_is_gone(&self, tree: &Tree, err: &Error) -> bool {
        self.config.auto_reconnect
            && matches!(err, Error::Disconnected | Error::ServerUnresponsive { .. })
            && self
                .connection_for_tree_ref(tree)
                .is_some_and(|conn| conn.can_reconnect())
    }

    /// The connection that owns `tree`, or `None` when this client has none
    /// for it.
    fn connection_for_tree_ref(&self, tree: &Tree) -> Option<&Connection> {
        if tree.server == self.primary_server {
            Some(&self.conn)
        } else {
            self.extra_connections.get(&tree.server).map(|e| &e.conn)
        }
    }

    /// Bring the tree's own connection back and re-establish `tree` on the new
    /// session.
    ///
    /// Works for a DFS target as well as the primary. A namespace root makes
    /// the *target* connection the one carrying all of the user's traffic, so
    /// "only the primary recovers" meant the connection that mattered did not.
    /// Reviving one says nothing about the other: each has its own socket and
    /// its own session, and only the tree's own is touched.
    async fn recover_tree(&mut self, tree: &mut Tree) -> Result<()> {
        let share = tree.share_name.clone();

        if tree.server == self.primary_server {
            self.conn.reconnect_if_needed().await?;
            self.refresh_session();
            // In place, exactly as the DFS redirect does: the caller keeps
            // using the `&mut Tree` it passed in, now pointing at the new
            // session's tree id.
            *tree = self.connect_share(&share).await?;
            return Ok(());
        }

        let addr = tree.server.clone();
        let entry = self
            .extra_connections
            .get_mut(&addr)
            .ok_or(Error::Disconnected)?;
        entry.conn.reconnect_if_needed().await?;
        // Adopt whatever session the revival established. ❌ Skipping this is
        // not cosmetic: `ensure_tree` activates share encryption from these
        // keys, and the dead session's keys decrypt nothing.
        if let Some(current) = entry.conn.current_session() {
            entry.session = current;
        }
        *tree = self.ensure_tree(&addr, &share).await?;
        Ok(())
    }

    // ── Convenience methods that delegate to Tree ──────────────────────

    /// List files in a directory on the given share.
    ///
    /// This is a convenience wrapper around [`Tree::list_directory`] that
    /// saves you from threading `connection_mut()` through every call.
    /// If the server returns a DFS referral, the tree is updated in-place
    /// and the operation is retried on the target server.
    pub async fn list_directory(
        &mut self,
        tree: &mut Tree,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.list_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.list_directory(conn, &new_path).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.list_directory(conn, path).await
            }
            other => other,
        }
    }

    /// Read a file from the given share.
    pub async fn read_file(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.read_file(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file(conn, &new_path).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file(conn, path).await
            }
            other => other,
        }
    }

    /// Read a small file using a compound CREATE+READ+CLOSE request.
    ///
    /// Sends all three operations in a single transport frame, reducing
    /// round-trips from 3 to 1. Best for files that fit in a single
    /// READ (up to MaxReadSize, typically 8 MB).
    pub async fn read_file_compound(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.read_file_compound(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file_compound(conn, &new_path).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file_compound(conn, path).await
            }
            other => other,
        }
    }

    /// Read a file using pipelined I/O (faster for large files).
    pub async fn read_file_pipelined(&mut self, tree: &mut Tree, path: &str) -> Result<Vec<u8>> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.read_file_pipelined(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file_pipelined(conn, &new_path).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.read_file_pipelined(conn, path).await
            }
            other => other,
        }
    }

    /// Write data to a file on the given share (create or overwrite).
    pub async fn write_file(&mut self, tree: &mut Tree, path: &str, data: &[u8]) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.write_file(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.write_file(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Write a small file using a compound CREATE+WRITE+FLUSH+CLOSE request.
    ///
    /// Sends all four operations in a single transport frame, reducing
    /// round-trips from 4 to 1. Best for files that fit in MaxWriteSize
    /// (typically 64 KB to 8 MB). For larger files, use
    /// [`write_file_pipelined`](Self::write_file_pipelined).
    pub async fn write_file_compound(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.write_file_compound(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.write_file_compound(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Write data to a file using pipelined I/O (faster for large files).
    pub async fn write_file_pipelined(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
    ) -> Result<u64> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.write_file_pipelined(conn, path, data).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.write_file_pipelined(conn, &new_path, data).await
            }
            other => other,
        }
    }

    /// Query file system space information for the given share.
    ///
    /// Returns total capacity, free space, and allocation unit sizes.
    /// Uses a compound CREATE+QUERY_INFO+CLOSE for efficiency (one round-trip).
    pub async fn fs_info(&mut self, tree: &mut Tree) -> Result<tree::FsInfo> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.fs_info(conn).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                // fs_info has no path argument -- the DFS redirect uses
                // the root of the share as the path.
                let _new_path = self.handle_dfs_redirect(tree, "").await?;
                let conn = self.connection_for_tree(tree)?;
                tree.fs_info(conn).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.fs_info(conn).await
            }
            other => other,
        }
    }

    /// Delete a file on the given share.
    pub async fn delete_file(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.delete_file(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.delete_file(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Delete multiple files on the given share.
    ///
    /// Returns results in the same order as the input paths.
    ///
    /// Each item costs one round trip and they do not overlap, so this saves
    /// the per-call setup rather than the wire time. To overlap server work,
    /// run the single-item call on several connections concurrently.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn delete_files(&mut self, tree: &mut Tree, paths: &[&str]) -> Vec<Result<()>> {
        let conn = match self.connection_for_tree(tree) {
            Ok(conn) => conn,
            Err(_) => return no_connection_results(paths.len()),
        };
        tree.delete_files(conn, paths).await
    }

    /// Get file metadata (size, timestamps, whether it's a directory).
    pub async fn stat(&mut self, tree: &mut Tree, path: &str) -> Result<FileInfo> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.stat(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.stat(conn, &new_path).await
            }
            Err(e) if self.session_is_gone(tree, &e) => {
                self.recover_tree(tree).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.stat(conn, path).await
            }
            other => other,
        }
    }

    /// Stat multiple files on the given share.
    ///
    /// Returns results in the same order as the input paths. To describe a
    /// whole directory, `list_directory` is far cheaper than a stat per entry.
    ///
    /// Each item costs one round trip and they do not overlap, so this saves
    /// the per-call setup rather than the wire time. To overlap server work,
    /// run the single-item call on several connections concurrently.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn stat_files(&mut self, tree: &mut Tree, paths: &[&str]) -> Vec<Result<FileInfo>> {
        let conn = match self.connection_for_tree(tree) {
            Ok(conn) => conn,
            Err(_) => return no_connection_results(paths.len()),
        };
        tree.stat_files(conn, paths).await
    }

    /// Rename a file or directory on the given share.
    pub async fn rename(&mut self, tree: &mut Tree, from: &str, to: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.rename(conn, from, to).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, from).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.rename(conn, &new_path, to).await
            }
            other => other,
        }
    }

    /// Rename multiple files on the given share.
    ///
    /// Returns results in the same order as the input pairs.
    ///
    /// Each item costs one round trip and they do not overlap, so this saves
    /// the per-call setup rather than the wire time. To overlap server work,
    /// run the single-item call on several connections concurrently.
    ///
    /// Note: DFS retry is not applied to batch operations. If the share
    /// is a DFS target, perform a single-file operation first to trigger
    /// the redirect, then use the batch method on the resolved tree.
    pub async fn rename_files(
        &mut self,
        tree: &mut Tree,
        renames: &[(&str, &str)],
    ) -> Vec<Result<()>> {
        let conn = match self.connection_for_tree(tree) {
            Ok(conn) => conn,
            Err(_) => return no_connection_results(renames.len()),
        };
        tree.rename_files(conn, renames).await
    }

    /// Create a directory on the given share.
    pub async fn create_directory(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.create_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.create_directory(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Delete an empty directory on the given share.
    pub async fn delete_directory(&mut self, tree: &mut Tree, path: &str) -> Result<()> {
        let result = {
            let conn = self.connection_for_tree(tree)?;
            tree.delete_directory(conn, path).await
        };
        match result {
            Err(e) if self.should_retry_dfs(&e) => {
                let new_path = self.handle_dfs_redirect(tree, path).await?;
                let conn = self.connection_for_tree(tree)?;
                tree.delete_directory(conn, &new_path).await
            }
            other => other,
        }
    }

    /// Start a streaming file download (memory-efficient for large files).
    ///
    /// Returns a [`FileDownload`] that yields chunks one at a time without
    /// buffering the entire file in memory. Each call to
    /// [`next_chunk`](FileDownload::next_chunk) sends one READ request.
    ///
    /// The connection is borrowed mutably for the lifetime of the download,
    /// so no other operations can run concurrently. This prevents accidental
    /// interleaving of SMB messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
    /// use tokio::io::AsyncWriteExt;
    ///
    /// let mut download = client.download(&share, "big_video.mp4").await?;
    /// println!("Downloading {} bytes...", download.size());
    ///
    /// let mut file = tokio::fs::File::create("big_video.mp4").await?;
    /// while let Some(chunk) = download.next_chunk().await {
    ///     let bytes = chunk?;
    ///     file.write_all(&bytes).await?;
    ///     println!("{:.1}%", download.progress().percent());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
    ) -> Result<FileDownload<'a>> {
        tree.download(&mut self.conn, path).await
    }

    /// Start a streaming file upload with progress tracking.
    ///
    /// Returns a [`FileUpload`] that writes data in chunks. Each call to
    /// [`write_next_chunk`](FileUpload::write_next_chunk) sends one WRITE
    /// request and reports progress.
    ///
    /// For small files (data fits in one MaxWriteSize), the data is written
    /// immediately via a compound CREATE+WRITE+FLUSH+CLOSE request in the
    /// constructor. The returned `FileUpload` is already complete, and
    /// `write_next_chunk` returns `false` immediately. This gives the caller
    /// a uniform API regardless of file size.
    ///
    /// The connection is borrowed mutably for the lifetime of the upload,
    /// so no other operations can run concurrently. This prevents accidental
    /// interleaving of SMB messages.
    ///
    /// # Example
    ///
    /// ```ignore
    /// # async fn example(client: &mut smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
    /// let data = std::fs::read("large_video.mp4")?;
    /// let mut upload = client.upload(&share, "remote_video.mp4", &data).await?;
    /// println!("Uploading {} bytes...", upload.total_bytes());
    ///
    /// while upload.write_next_chunk().await? {
    ///     println!("{:.1}%", upload.progress().percent());
    /// }
    /// // File is flushed and closed automatically after the last chunk.
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upload<'a>(
        &'a mut self,
        tree: &'a Tree,
        path: &str,
        data: &'a [u8],
    ) -> Result<stream::FileUpload<'a>> {
        let max_write = self
            .conn
            .params()
            .map(|p| p.max_write_size as usize)
            .unwrap_or(65536);

        if data.len() <= max_write {
            // Small file: write everything via compound in one round-trip.
            tree.write_file_compound(&mut self.conn, path, data).await?;
            Ok(stream::FileUpload::new_done(
                tree,
                &mut self.conn,
                data.len() as u64,
            ))
        } else {
            // Large file: open the file, let the caller drive chunks.
            let file_id = tree.open_file_for_write(&mut self.conn, path).await?;
            let chunk_size = max_write as u32;
            Ok(stream::FileUpload::new(
                tree,
                &mut self.conn,
                file_id,
                data,
                chunk_size,
            ))
        }
    }

    /// Open a random-access [`FileReader`](stream::FileReader) over a file on
    /// the share.
    ///
    /// Clones the client's primary connection (cheap `Arc::clone`) and the
    /// `Tree`, then returns a reader that serves any number of positioned reads
    /// at arbitrary offsets over one open handle. The returned reader is
    /// `'static` and does not borrow the client, so concurrent readers proceed
    /// in parallel over the single SMB session. Call
    /// [`FileReader::close`](stream::FileReader::close) when done.
    ///
    /// No DFS retry; the reader pins to the connection it was built from.
    pub async fn open_file_reader(&self, tree: &Tree, path: &str) -> Result<stream::FileReader> {
        stream::open_file_reader(std::sync::Arc::new(tree.clone()), self.conn.clone(), path).await
    }

    /// Create a push-based pipelined streaming file writer.
    ///
    /// Opens (or creates) the file for writing and returns a [`FileWriter`]
    /// that the caller drives by pushing data chunks. The returned writer
    /// owns a cheap `Arc::clone` of `Connection` and an `Arc<Tree>` — it
    /// is `'static` and does not borrow from the client. Multiple writers
    /// built this way pipeline their WRITEs over a single SMB session
    /// without external locking.
    ///
    /// No DFS retry; the writer pins to the connection it was built from.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(client: &smb2::SmbClient, share: &smb2::Tree) -> Result<(), smb2::Error> {
    /// let mut writer = client.create_file_writer(share, "output.bin").await?;
    /// writer.write_chunk(b"hello").await?;
    /// writer.write_chunk(b" world").await?;
    /// let total = writer.finish().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_file_writer(&self, tree: &Tree, path: &str) -> Result<stream::FileWriter> {
        // Convenience wrapper: clone the primary connection (cheap
        // `Arc::clone`) and the `Tree` into an `Arc`, then build a writer
        // that owns both. The client's connection is not borrowed for the
        // upload's duration, so concurrent writers proceed in parallel.
        stream::open_file_writer(std::sync::Arc::new(tree.clone()), self.conn.clone(), path).await
    }

    /// Exclusive-create sibling of [`create_file_writer`](Self::create_file_writer).
    ///
    /// Same shape, but the CREATE uses `FileCreate` disposition: if the file
    /// already exists the open fails with
    /// [`crate::ErrorKind::AlreadyExists`]. Use
    /// this for race-free "create only if absent" writes — for example, a
    /// file manager's "New File" action where silently clobbering an
    /// existing file is unsafe.
    pub async fn create_file_writer_exclusive(
        &self,
        tree: &Tree,
        path: &str,
    ) -> Result<stream::FileWriter> {
        stream::open_file_writer_exclusive(
            std::sync::Arc::new(tree.clone()),
            self.conn.clone(),
            path,
        )
        .await
    }

    /// Create a positioned push-based streaming file writer.
    ///
    /// Same shape as [`create_file_writer`](Self::create_file_writer), but the
    /// file is opened without truncating and the writer's first byte lands at
    /// `offset`. Use it to append after a server-side-copied prefix (see
    /// [`server_side_copy_range`](Tree::server_side_copy_range)) or to patch a
    /// known region of an existing file.
    ///
    /// No DFS retry; the writer pins to the connection it was built from.
    pub async fn create_file_writer_at(
        &self,
        tree: &Tree,
        path: &str,
        offset: u64,
    ) -> Result<stream::FileWriter> {
        stream::open_file_writer_at(
            std::sync::Arc::new(tree.clone()),
            self.conn.clone(),
            path,
            offset,
        )
        .await
    }

    /// Read a file with progress reporting and cancellation.
    ///
    /// Uses pipelined I/O for performance, calling `on_progress` after each
    /// chunk is received. Return `ControlFlow::Break(())` to cancel the read.
    pub async fn read_file_with_progress<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        on_progress: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        // DFS retry is not straightforward with progress callbacks (the
        // callback is consumed by the first attempt). For now, attempt
        // the operation directly. If DFS redirect is needed, the caller
        // should resolve the tree first using a simpler method.
        let conn = self.connection_for_tree(tree)?;
        tree.read_file_pipelined_with_progress(conn, path, on_progress)
            .await
    }

    /// Write a file with progress reporting and cancellation.
    ///
    /// Writes data in chunks, calling `on_progress` after each chunk.
    /// Return `ControlFlow::Break(())` to cancel the write.
    ///
    /// The file is flushed before closing to ensure data is persisted
    /// on the server.
    pub async fn write_file_with_progress<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        data: &[u8],
        mut on_progress: F,
    ) -> Result<u64>
    where
        F: FnMut(Progress) -> ControlFlow<()>,
    {
        // Open the file for writing.
        let req = crate::msg::create::CreateRequest {
            requested_oplock_level: crate::types::OplockLevel::None,
            impersonation_level: crate::msg::create::ImpersonationLevel::Impersonation,
            desired_access: crate::types::flags::FileAccessMask::new(
                crate::types::flags::FileAccessMask::FILE_WRITE_DATA
                    | crate::types::flags::FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | crate::types::flags::FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            share_access: crate::msg::create::ShareAccess(0),
            create_disposition: crate::msg::create::CreateDisposition::FileOverwriteIf,
            create_options: 0x0000_0040, // FILE_NON_DIRECTORY_FILE
            name: tree.format_path(path),
            create_contexts: vec![],
        };

        let frame = self
            .conn
            .execute(crate::types::Command::Create, &req, Some(tree.tree_id))
            .await?;

        if frame.header.status != crate::types::status::NtStatus::SUCCESS {
            return Err(crate::Error::Protocol {
                status: frame.header.status,
                command: crate::types::Command::Create,
            });
        }

        let mut cursor = crate::pack::ReadCursor::new(&frame.body);
        let create_resp = crate::msg::create::CreateResponse::unpack(&mut cursor)?;
        let file_id = create_resp.file_id;

        let max_write = self
            .conn
            .params()
            .map(|p| p.max_write_size)
            .unwrap_or(65536);

        let mut total_written = 0u64;
        let mut offset = 0usize;
        let mut cancelled = false;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = remaining.min(max_write as usize);
            let chunk = &data[offset..offset + chunk_size];

            let write_req = crate::msg::write::WriteRequest {
                data_offset: 0x70,
                offset: offset as u64,
                file_id,
                channel: 0,
                remaining_bytes: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: 0,
                data: chunk.to_vec(),
            };

            let credit_charge = credits::charge_for_payload(chunk_size as u64);
            let frame = self
                .conn
                .execute_with_credits(
                    crate::types::Command::Write,
                    &write_req,
                    Some(tree.tree_id),
                    crate::types::CreditCharge(credit_charge),
                )
                .await?;

            if frame.header.status != crate::types::status::NtStatus::SUCCESS {
                // Close handle before returning error.
                let _ = tree.close_handle(&mut self.conn, file_id).await;
                return Err(crate::Error::Protocol {
                    status: frame.header.status,
                    command: crate::types::Command::Write,
                });
            }

            let mut cursor = crate::pack::ReadCursor::new(&frame.body);
            let resp = crate::msg::write::WriteResponse::unpack(&mut cursor)?;

            total_written += resp.count as u64;
            offset += chunk_size;

            let progress = Progress {
                bytes_transferred: total_written,
                total_bytes: Some(data.len() as u64),
            };

            if let ControlFlow::Break(()) = on_progress(progress) {
                cancelled = true;
                break;
            }
        }

        if cancelled {
            // Best-effort close without flush.
            let _ = tree.close_handle(&mut self.conn, file_id).await;
            return Err(crate::Error::Cancelled);
        }

        // Flush to ensure data is persisted.
        tree.flush_handle(&mut self.conn, file_id).await?;

        // Close the handle.
        tree.close_handle(&mut self.conn, file_id).await?;

        Ok(total_written)
    }

    /// Write a file from a streaming source using pipelined I/O.
    ///
    /// Pulls data on demand from a callback, so you never need the full
    /// file in memory. See [`Tree::write_file_streamed`] for the full
    /// callback contract, performance characteristics, and usage guide.
    ///
    /// DFS retry is not supported for streamed writes (the callback is
    /// consumed by the first attempt). If the share uses DFS, resolve
    /// the tree first using a simpler method.
    pub async fn write_file_streamed<F>(
        &mut self,
        tree: &mut Tree,
        path: &str,
        next_chunk: &mut F,
    ) -> Result<u64>
    where
        F: FnMut() -> Option<std::result::Result<Vec<u8>, std::io::Error>>,
    {
        let conn = self.connection_for_tree(tree)?;
        tree.write_file_streamed(conn, path, next_chunk).await
    }

    /// Flush a file to ensure data is persisted on the server.
    ///
    /// This sends an SMB2 FLUSH request for the given file handle.
    /// Write methods (`write_file`, `write_file_pipelined`,
    /// `write_file_with_progress`) flush automatically before closing.
    /// Use this if you need to flush a handle obtained through the
    /// low-level API.
    pub async fn flush_file(&mut self, tree: &mut Tree, file_id: FileId) -> Result<()> {
        let conn = self.connection_for_tree(tree)?;
        tree.flush_handle(conn, file_id).await
    }

    /// Watch a directory for changes.
    ///
    /// Opens the directory and returns a [`Watcher`] that yields change
    /// events. The server holds each request until changes occur (long poll).
    ///
    /// Set `recursive` to `true` to watch the entire subtree.
    ///
    /// The returned `Watcher` owns a cloned connection (cheap `Arc::clone`,
    /// all clones multiplex over the same SMB session), so this client
    /// remains usable for other operations while watching.
    pub async fn watch(&mut self, tree: &Tree, path: &str, recursive: bool) -> Result<Watcher> {
        tree.watch(&mut self.conn, path, recursive).await
    }

    /// Disconnect from a share.
    pub async fn disconnect_share(&mut self, tree: &Tree) -> Result<()> {
        let conn = self.connection_for_tree(tree)?;
        tree.disconnect(conn).await
    }
}

/// Connect to an SMB server with the simplest possible API.
///
/// This is a shorthand for creating a [`ClientConfig`] and calling
/// [`SmbClient::connect`]. Uses a five-second timeout and no auto-reconnect.
pub async fn connect(addr: &str, username: &str, password: &str) -> Result<SmbClient> {
    SmbClient::connect(ClientConfig {
        addr: addr.to_string(),
        timeout: Duration::from_secs(5),
        username: username.to_string(),
        password: password.to_string(),
        domain: String::new(),
        auto_reconnect: false,
        compression: true,
        dfs_enabled: true,
        dfs_target_overrides: std::collections::HashMap::new(),
        connect_options: None,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::connection::pack_message;
    use crate::client::test_helpers::build_tree_connect_response;
    use crate::msg::header::Header;
    use crate::msg::negotiate::{NegotiateContext, NegotiateResponse, HASH_ALGORITHM_SHA512};
    use crate::msg::session_setup::{SessionFlags, SessionSetupResponse};
    use crate::msg::tree_connect::ShareType;
    use crate::pack::Guid;
    use crate::transport::MockTransport;
    use crate::types::flags::{Capabilities, SecurityMode};
    use crate::types::status::NtStatus;
    use crate::types::{Command, Dialect, SessionId, TreeId};
    use std::sync::Arc;

    /// Build a negotiate response.
    fn build_negotiate_response() -> Vec<u8> {
        let mut h = Header::new_request(Command::Negotiate);
        h.flags.set_response();
        h.credits = 32;
        let body = NegotiateResponse {
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: Dialect::Smb3_1_1,
            server_guid: Guid::ZERO,
            capabilities: Capabilities::new(Capabilities::DFS | Capabilities::LEASING),
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: 132_000_000_000_000_000,
            server_start_time: 131_000_000_000_000_000,
            security_buffer: vec![0x60, 0x00],
            negotiate_contexts: vec![NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HASH_ALGORITHM_SHA512],
                salt: vec![0xBB; 32],
            }],
        };
        pack_message(&h, &body)
    }

    /// Build a session setup response.
    fn build_session_setup_response(
        status: NtStatus,
        session_id: SessionId,
        security_buffer: Vec<u8>,
        session_flags: SessionFlags,
    ) -> Vec<u8> {
        let mut h = Header::new_request(Command::SessionSetup);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;
        h.session_id = session_id;

        let body = SessionSetupResponse {
            session_flags,
            security_buffer,
        };

        pack_message(&h, &body)
    }

    /// Build a minimal NTLM challenge message (Type 2).
    fn build_ntlm_challenge() -> Vec<u8> {
        let mut buf = Vec::new();

        // Signature
        buf.extend_from_slice(b"NTLMSSP\0");
        // MessageType = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // TargetNameFields: Len=0, MaxLen=0, Offset=56
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&56u32.to_le_bytes());
        // NegotiateFlags
        let flags: u32 = 0x0000_0001 // UNICODE
            | 0x0000_0200  // NTLM
            | 0x0008_0000  // EXTENDED_SESSIONSECURITY
            | 0x0080_0000  // TARGET_INFO
            | 0x2000_0000  // 128
            | 0x4000_0000  // KEY_EXCH
            | 0x8000_0000  // 56
            | 0x0000_0010  // SIGN
            | 0x0000_0020; // SEAL
        buf.extend_from_slice(&flags.to_le_bytes());
        // ServerChallenge
        buf.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        // Reserved
        buf.extend_from_slice(&[0u8; 8]);
        // TargetInfoFields
        let target_info = {
            let mut ti = Vec::new();
            ti.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL AvId=0
            ti.extend_from_slice(&0u16.to_le_bytes()); // AvLen=0
            ti
        };
        let ti_offset = 56u32;
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
        buf.extend_from_slice(&ti_offset.to_le_bytes());
        while buf.len() < 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&target_info);
        buf
    }

    /// Queue negotiate + session setup responses on a mock transport.
    fn queue_negotiate_and_session(mock: &MockTransport, session_id: SessionId) {
        mock.queue_response(build_negotiate_response());

        let challenge = build_ntlm_challenge();
        mock.queue_response(build_session_setup_response(
            NtStatus::MORE_PROCESSING_REQUIRED,
            session_id,
            challenge,
            SessionFlags(0),
        ));

        mock.queue_response(build_session_setup_response(
            NtStatus::SUCCESS,
            session_id,
            vec![],
            SessionFlags(0),
        ));
    }

    /// Create a mock-backed SmbClient without going through TCP.
    async fn make_mock_client(mock: &Arc<MockTransport>, session_id: SessionId) -> SmbClient {
        mock.enable_auto_rewrite_msg_id();
        queue_negotiate_and_session(mock, session_id);

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );

        conn.negotiate().await.unwrap();

        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: false,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: std::collections::HashMap::new(),
            connect_options: None,
        };

        SmbClient::from_parts(config, conn, session)
    }

    /// A TREE_CONNECT response for a share that demands encryption.
    fn build_encrypting_tree_connect_response(tree_id: TreeId) -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeConnect);
        h.flags.set_response();
        h.credits = 32;
        h.tree_id = Some(tree_id);

        let body = crate::msg::tree_connect::TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: crate::types::flags::ShareFlags::new(
                crate::types::flags::ShareFlags::ENCRYPT_DATA,
            ),
            capabilities: crate::types::flags::ShareCapabilities::default(),
            maximal_access: 0x001F_01FF,
        };
        pack_message(&h, &body)
    }

    /// A session with SMB 3.x encryption keys, which is what session setup
    /// produces on a dialect that supports encryption.
    fn session_with_keys(session_id: SessionId) -> Session {
        Session {
            session_id,
            signing_key: vec![0x11; 16],
            encryption_key: Some(vec![0x22; 16]),
            decryption_key: Some(vec![0x33; 16]),
            signing_algorithm: crate::crypto::signing::SigningAlgorithm::HmacSha256,
            should_sign: false,
            should_encrypt: false,
        }
    }

    /// Put an extra connection in the DFS pool, the way a redirect to another
    /// server does.
    fn pool_extra_connection(client: &mut SmbClient, addr: &str, mock: &Arc<MockTransport>) {
        let conn = crate::client::test_helpers::setup_connection(mock);
        client.extra_connections.insert(
            addr.to_string(),
            ConnectionEntry {
                conn,
                session: std::sync::Arc::new(session_with_keys(SessionId(0x99))),
            },
        );
    }

    fn a_dfs_target_tree(addr: &str, share: &str) -> Tree {
        Tree {
            tree_id: TreeId(5),
            share_name: share.to_string(),
            server: addr.to_string(),
            is_dfs: false,
            encrypt_data: false,
            dfs_origin: None,
        }
    }

    /// `auto_reconnect` has to cover the connection the tree actually lives
    /// on. On a namespace root that is the *target* connection, carrying all
    /// of the user's traffic; asking the primary about it said "this is
    /// revivable" when it was not, and "this is not" when it was.
    #[tokio::test]
    async fn liveness_is_judged_on_the_trees_own_connection() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;
        client.config.auto_reconnect = true;
        // The primary is armed; the DFS target is not.
        client
            .conn
            .set_reviver(Some(Arc::new(MockReviver::new(SessionId(0x1)))));

        let target_mock = Arc::new(MockTransport::new());
        pool_extra_connection(&mut client, "dfs-target:445", &target_mock);

        let target_tree = a_dfs_target_tree("dfs-target:445", "secret");
        assert!(
            !client.session_is_gone(&target_tree, &Error::Disconnected),
            "the primary's reviver says nothing about the target connection"
        );

        // Arm the target, and it becomes recoverable.
        client.extra_connections["dfs-target:445"]
            .conn
            .set_reviver(Some(Arc::new(MockReviver::new(SessionId(0x2)))));
        assert!(client.session_is_gone(&target_tree, &Error::Disconnected));

        // A tree on a server this client has no connection for is never
        // "recoverable", whatever the primary says.
        let stranger = a_dfs_target_tree("somewhere-else:445", "secret");
        assert!(!client.session_is_gone(&stranger, &Error::Disconnected));
    }

    // ── DFS namespace roots ───────────────────────────────────────────

    /// A TREE_CONNECT refusal, optionally carrying the cluster-redirect error
    /// context that reuses the same status code.
    fn build_tree_connect_refusal(status: NtStatus, share_redirect: bool) -> Vec<u8> {
        let mut h = Header::new_request(Command::TreeConnect);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;

        let (error_context_count, error_data) = if share_redirect {
            // One SMB2 ERROR Context: ErrorDataLength(4) + ErrorId(4) + a
            // Share Redirect body we never look inside.
            let body = vec![0u8; 48];
            let mut data = Vec::new();
            data.extend_from_slice(&(body.len() as u32).to_le_bytes());
            data.extend_from_slice(&0x7264_5253u32.to_le_bytes());
            data.extend_from_slice(&body);
            (1u8, data)
        } else {
            (0u8, Vec::new())
        };

        pack_message(
            &h,
            &crate::msg::header::ErrorResponse {
                error_context_count,
                error_data,
            },
        )
    }

    /// A Samba-shaped V3 root referral: `ServerType = 0`.
    fn build_root_referral(namespace: &str, targets: &[&str], header_flags: u32) -> Vec<u8> {
        build_referral(3, 0, namespace, targets, header_flags)
    }

    /// A referral at a chosen version and `ServerType`, wrapped in an IOCTL
    /// response.
    fn build_referral(
        version: u16,
        server_type: u16,
        namespace: &str,
        targets: &[&str],
        header_flags: u32,
    ) -> Vec<u8> {
        let entries: Vec<(&str, &str, &str, u32)> = targets
            .iter()
            .map(|t| (namespace, namespace, *t, 600u32))
            .collect();
        let payload = crate::client::dfs::tests::pack_referral(
            version,
            server_type,
            (namespace.encode_utf16().count() * 2) as u16,
            header_flags,
            &entries,
        );

        let mut h = Header::new_request(Command::Ioctl);
        h.flags.set_response();
        h.credits = 32;
        pack_message(
            &h,
            &crate::msg::ioctl::IoctlResponse {
                ctl_code: crate::msg::ioctl::FSCTL_DFS_GET_REFERRALS,
                file_id: FileId::SENTINEL,
                flags: crate::msg::ioctl::SMB2_0_IOCTL_IS_FSCTL,
                output_data: payload,
            },
        )
    }

    fn build_ioctl_refusal(status: NtStatus) -> Vec<u8> {
        let mut h = Header::new_request(Command::Ioctl);
        h.flags.set_response();
        h.credits = 32;
        h.status = status;
        pack_message(
            &h,
            &crate::msg::header::ErrorResponse {
                error_context_count: 0,
                error_data: vec![],
            },
        )
    }

    /// The headline: a namespace root is not a share on the server answering
    /// its name, so `TREE_CONNECT` is refused and only a referral can say
    /// where the storage actually is. Before this, the path could not be
    /// opened at all.
    #[tokio::test]
    async fn a_namespace_root_resolves_to_the_target_the_referral_names() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        // The share the caller named isn't one: STATUS_BAD_NETWORK_NAME.
        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        // IPC$ for the referral, then the referral itself. Samba's shape:
        // ServerType 0 and StorageServers alone.
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\aleu_dfs"],
            0x02,
        ));
        // And the tree connect to the target share.
        mock.queue_response(build_tree_connect_response(TreeId(9), ShareType::Disk));

        let tree = client
            .connect_share("aleu")
            .await
            .expect("a namespace root must resolve");

        assert_eq!(tree.tree_id, TreeId(9));
        assert_eq!(tree.share_name, "aleu_dfs");
        assert_eq!(
            tree.dfs_origin,
            Some(DfsOrigin {
                requested: r"\\test-server\aleu".to_string(),
                target: r"\\test-server\aleu_dfs".to_string(),
            }),
            "the caller's own name for the namespace has to survive the redirect"
        );
    }

    /// Windows and Samba answer the *same* root referral differently, and both
    /// must resolve identically.
    ///
    /// Windows sets `ServerType = 1` and both header bits (MS-DFSC § 4.3,
    /// § 4.6); Samba answers `ServerType = 0` and StorageServers alone
    /// (verified against Samba 4.20.6, 2026-09-16). ❌ Nothing may gate on
    /// `ServerType`: a client that requires 1 works against Windows and
    /// silently refuses every Samba namespace. The Docker fixtures only ever
    /// produce the Samba shape, so this is the side they cannot cover.
    #[tokio::test]
    async fn windows_and_samba_shaped_root_referrals_resolve_the_same() {
        // (version, server_type, header_flags)
        let shapes = [
            (4u16, 1u16, 0x03u32, "Windows"),
            (3, 0, 0x02, "Samba"),
            // A Windows-shaped V3, which § 4.3's text also allows.
            (3, 1, 0x03, "Windows V3"),
        ];

        for (version, server_type, header_flags, who) in shapes {
            let mock = Arc::new(MockTransport::new());
            let mut client = make_mock_client(&mock, SessionId(0x77)).await;

            mock.queue_response(build_tree_connect_refusal(
                NtStatus::BAD_NETWORK_NAME,
                false,
            ));
            mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
            mock.queue_response(build_referral(
                version,
                server_type,
                r"\test-server\aleu",
                &[r"\test-server\aleu_dfs"],
                header_flags,
            ));
            mock.queue_response(build_tree_connect_response(TreeId(9), ShareType::Disk));

            let tree = client
                .connect_share("aleu")
                .await
                .unwrap_or_else(|e| panic!("a {who}-shaped root referral must resolve: {e}"));
            assert_eq!(tree.share_name, "aleu_dfs", "{who}");
            assert_eq!(
                tree.dfs_origin.as_ref().map(|o| o.requested.as_str()),
                Some(r"\\test-server\aleu"),
                "{who}"
            );
        }
    }

    /// ❌ A failed referral must not replace the original error. The
    /// overwhelmingly common cause of `STATUS_BAD_NETWORK_NAME` is a typo, and
    /// telling that person about DFS is worse than telling them nothing.
    #[tokio::test]
    async fn a_mistyped_share_name_still_reports_the_missing_share() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        // No namespace by that name either.
        mock.queue_response(build_ioctl_refusal(NtStatus::NOT_FOUND));

        let err = client.connect_share("shrae").await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Protocol {
                    status: NtStatus::BAD_NETWORK_NAME,
                    command: Command::TreeConnect
                }
            ),
            "expected the original refusal, got {err:?}"
        );
    }

    /// A referral that answers with no targets at all is the same story.
    #[tokio::test]
    async fn an_empty_referral_reports_the_missing_share() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        mock.queue_response(build_root_referral(r"\test-server\aleu", &[], 0x02));

        let err = client.connect_share("aleu").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol {
                status: NtStatus::BAD_NETWORK_NAME,
                ..
            }
        ));
    }

    /// A chain that ends empty is a chain that ended, not a hop limit that was
    /// reached. The caller gets the original refusal, and above all not a
    /// `DfsTooManyReferrals` naming a limit nothing came near.
    #[tokio::test]
    async fn an_empty_referral_after_an_interlink_is_not_a_hop_limit_error() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        // Hop 1: an interlink into a second namespace.
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\elsewhere"],
            0x01,
        ));
        // Hop 2: nothing there.
        mock.queue_response(build_root_referral(r"\test-server\elsewhere", &[], 0x02));

        let err = client.connect_share("aleu").await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Protocol {
                    status: NtStatus::BAD_NETWORK_NAME,
                    ..
                }
            ),
            "the chain ended after two hops, so the caller should get the \
             original refusal; got {err:?}"
        );
    }

    /// The one outcome that is genuinely about DFS: the namespace is real, we
    /// found it, and its storage is out of reach. No other error says that.
    #[tokio::test]
    async fn a_namespace_whose_targets_are_all_down_says_exactly_that() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\one", r"\test-server\two"],
            0x02,
        ));
        // Both targets refuse.
        mock.queue_response(build_tree_connect_refusal(NtStatus::ACCESS_DENIED, false));
        mock.queue_response(build_tree_connect_refusal(NtStatus::ACCESS_DENIED, false));

        let err = client.connect_share("aleu").await.unwrap_err();
        match err {
            Error::DfsNoReachableTarget {
                namespace,
                target_count,
                ..
            } => {
                assert_eq!(namespace, r"\\test-server\aleu");
                assert_eq!(target_count, 2);
            }
            other => panic!("expected DfsNoReachableTarget, got {other:?}"),
        }
    }

    /// § 3.1.4.1 step 2: the second connect goes straight to the target, so
    /// the refused TREE_CONNECT and the referral are paid once per TTL rather
    /// than once per connect.
    #[tokio::test]
    async fn a_known_namespace_skips_the_refused_tree_connect() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\aleu_dfs"],
            0x02,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(9), ShareType::Disk));

        client.connect_share("aleu").await.unwrap();
        let after_first = mock.sent_count();

        mock.queue_response(build_tree_connect_response(TreeId(10), ShareType::Disk));
        let tree = client.connect_share("aleu").await.unwrap();

        assert_eq!(tree.tree_id, TreeId(10));
        assert!(tree.dfs_origin.is_some());
        assert_eq!(
            mock.sent_count() - after_first,
            1,
            "a cached namespace should cost one tree connect, nothing else"
        );
    }

    /// `STATUS_BAD_NETWORK_NAME` with an `SMB2_ERROR_ID_SHARE_REDIRECT`
    /// context is scale-out cluster redirection (MS-SMB2 § 2.2.2.2.2), an
    /// unrelated mechanism reusing the same status. Chasing a DFS referral
    /// for it would be nonsense, so it never gets one.
    #[tokio::test]
    async fn a_cluster_redirect_is_not_mistaken_for_a_namespace() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(NtStatus::BAD_NETWORK_NAME, true));
        let before = mock.sent_count();

        let err = client.connect_share("clustered").await.unwrap_err();
        assert!(
            matches!(&err, Error::ShareRedirected { share } if share == "clustered"),
            "expected ShareRedirected, got {err:?}"
        );
        assert_eq!(
            mock.sent_count() - before,
            1,
            "no referral should be sent for a cluster redirect"
        );
    }

    /// A server that never advertised `SMB2_GLOBAL_CAP_DFS` is not asked for
    /// a referral, so a plain NAS pays nothing when someone mistypes a share.
    #[tokio::test]
    async fn a_server_without_cap_dfs_is_never_asked_for_a_referral() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;
        client.conn.set_test_params(NegotiatedParams {
            dialect: Dialect::Smb3_1_1,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(), // no DFS
            gmac_negotiated: false,
            cipher: None,
            compression_supported: false,
        });

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        let before = mock.sent_count();

        let err = client.connect_share("aleu").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol {
                status: NtStatus::BAD_NETWORK_NAME,
                ..
            }
        ));
        assert_eq!(mock.sent_count() - before, 1, "no referral round trip");
    }

    /// § 3.1.5.4.5: ReferralServers set with StorageServers clear means the
    /// target lives in another namespace, so it is re-resolved rather than
    /// connected.
    #[tokio::test]
    async fn an_interlink_is_resolved_again_rather_than_connected() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        // R set, S clear: an interlink pointing at a second namespace.
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\elsewhere"],
            0x01,
        ));
        // The second namespace resolves normally.
        mock.queue_response(build_root_referral(
            r"\test-server\elsewhere",
            &[r"\test-server\real_share"],
            0x02,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(9), ShareType::Disk));

        let tree = client.connect_share("aleu").await.unwrap();
        assert_eq!(tree.share_name, "real_share");
        assert_eq!(
            tree.dfs_origin.unwrap().requested,
            r"\\test-server\aleu",
            "the caller's name survives however many hops it took"
        );
    }

    /// A namespace that refers to itself would resolve forever. It stops at
    /// `MAX_DFS_HOPS` with an error naming the path, not a hang.
    #[tokio::test]
    async fn a_namespace_that_refers_to_itself_stops() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        mock.queue_response(build_tree_connect_refusal(
            NtStatus::BAD_NETWORK_NAME,
            false,
        ));
        mock.queue_response(build_tree_connect_response(TreeId(2), ShareType::Pipe));
        // An interlink naming its own namespace. The cache answers every hop
        // after the first, so this is one frame and eight hops.
        mock.queue_response(build_root_referral(
            r"\test-server\aleu",
            &[r"\test-server\aleu"],
            0x01,
        ));

        let err = client.connect_share("aleu").await.unwrap_err();
        match err {
            Error::DfsTooManyReferrals { namespace, hops } => {
                assert_eq!(namespace, r"\\test-server\aleu");
                assert_eq!(hops, MAX_DFS_HOPS);
            }
            other => panic!("expected DfsTooManyReferrals, got {other:?}"),
        }
    }

    /// A `Tree` outlives the pool entry it was resolved on, and using it then
    /// has to be an error rather than a panic inside a library.
    ///
    /// `reconnect()` drops every extra connection while the consumer still
    /// holds the DFS-resolved `Tree` it had — which is exactly the state the
    /// reconnect docs tell them they are in. Routing that tree used to
    /// `.expect()` its way into a panic.
    #[tokio::test]
    async fn a_tree_whose_dfs_connection_is_gone_is_an_error_not_a_panic() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        let orphan = a_dfs_target_tree("dfs-target:445", "secret");
        assert!(matches!(
            client.connection_for_tree(&orphan),
            Err(Error::Disconnected)
        ));

        // The batch methods report per item, so they say it per item.
        let mut orphan = orphan;
        let results = client.stat_files(&mut orphan, &["a.txt", "b.txt"]).await;
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|r| matches!(r, Err(Error::Disconnected))));
    }

    /// `recover_tree` revives the DFS target's own connection and
    /// re-establishes the tree on it. It used to refuse outright, so a
    /// namespace root's session dying was unrecoverable.
    #[tokio::test]
    async fn a_dfs_target_tree_recovers_on_its_own_connection() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        let target_mock = Arc::new(MockTransport::new());
        pool_extra_connection(&mut client, "dfs-target:445", &target_mock);

        // The revived connection answers the re-tree-connect with a new id.
        let reviver = Arc::new(MockReviver::answering_with(
            SessionId(0xBEEF),
            vec![build_tree_connect_response(TreeId(77), ShareType::Disk)],
        ));

        let entry = client
            .extra_connections
            .get_mut("dfs-target:445")
            .expect("just pooled");
        entry.conn.set_reviver(Some(
            Arc::clone(&reviver) as Arc<dyn connection::SessionReviver>
        ));
        entry.conn.mark_dead();

        let mut tree = a_dfs_target_tree("dfs-target:445", "secret");
        client
            .recover_tree(&mut tree)
            .await
            .expect("a DFS target tree must be recoverable");

        assert_eq!(
            tree.tree_id,
            TreeId(77),
            "tree re-established on the new session"
        );
        assert_eq!(tree.server, "dfs-target:445", "still routed to the target");
        assert!(!client.extra_connections["dfs-target:445"]
            .conn
            .is_disconnected());
        // The primary was not touched.
        assert_eq!(client.session().session_id, SessionId(0x77));
    }

    /// A DFS target share that asks for encryption gets it.
    ///
    /// `ensure_tree` is the path every DFS target goes through, and it skipped
    /// the activation `connect_share` does — so a target share carrying
    /// `SMB2_SHAREFLAG_ENCRYPT_DATA` moved the user's files in the clear.
    /// Both now go through `activate_share_encryption`.
    #[tokio::test]
    async fn a_dfs_target_share_that_asks_for_encryption_gets_it() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        let target_mock = Arc::new(MockTransport::new());
        pool_extra_connection(&mut client, "dfs-target:445", &target_mock);

        target_mock.queue_response(build_encrypting_tree_connect_response(TreeId(5)));
        let tree = client
            .ensure_tree("dfs-target:445", "secret")
            .await
            .expect("tree connect to the DFS target failed");

        assert!(tree.encrypt_data);
        assert!(
            client.extra_connections["dfs-target:445"]
                .conn
                .should_encrypt(),
            "a DFS target share flagged SMB2_SHAREFLAG_ENCRYPT_DATA must be encrypted"
        );
    }

    /// A target share that did not ask for encryption does not get it, so the
    /// fix above cannot have quietly become "encrypt everything".
    #[tokio::test]
    async fn a_dfs_target_share_that_did_not_ask_is_left_alone() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x77)).await;

        let target_mock = Arc::new(MockTransport::new());
        pool_extra_connection(&mut client, "dfs-target:445", &target_mock);

        target_mock.queue_response(build_tree_connect_response(TreeId(5), ShareType::Disk));
        client.ensure_tree("dfs-target:445", "plain").await.unwrap();

        assert!(!client.extra_connections["dfs-target:445"]
            .conn
            .should_encrypt());
    }

    /// Without keys there is nothing to encrypt with, and silently pretending
    /// otherwise would be worse than leaving it off.
    #[tokio::test]
    async fn an_encrypting_share_without_session_keys_is_left_alone() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x78)).await;

        let keyless = Session {
            encryption_key: None,
            decryption_key: None,
            ..session_with_keys(SessionId(0x78))
        };
        let tree = Tree {
            tree_id: TreeId(1),
            share_name: "secret".to_string(),
            server: "test-server:445".to_string(),
            is_dfs: false,
            encrypt_data: true,
            dfs_origin: None,
        };

        activate_share_encryption(client.connection_mut(), &keyless, &tree);
        assert!(!client.connection_mut().should_encrypt());
    }

    #[tokio::test]
    async fn smb_client_connect_via_mock_negotiates_and_authenticates() {
        let mock = Arc::new(MockTransport::new());
        let session_id = SessionId(0xABCD);

        let client = make_mock_client(&mock, session_id).await;

        assert_eq!(client.session().session_id, session_id);
        assert!(client.params().is_some());
        assert_eq!(client.params().unwrap().dialect, Dialect::Smb3_1_1);
    }

    #[tokio::test]
    async fn smb_client_stores_config() {
        let mock = Arc::new(MockTransport::new());
        let client = make_mock_client(&mock, SessionId(1)).await;

        assert_eq!(client.config().addr, "test-server:445");
        assert_eq!(client.config().username, "user");
        assert_eq!(client.config().password, "pass");
        assert!(!client.config().auto_reconnect);
    }

    #[tokio::test]
    async fn smb_client_connect_share_returns_tree() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(1)).await;

        // Queue tree connect response.
        mock.queue_response(crate::client::test_helpers::build_tree_connect_response(
            TreeId(42),
            ShareType::Disk,
        ));

        let tree = client.connect_share("TestShare").await.unwrap();
        assert_eq!(tree.tree_id, TreeId(42));
        assert_eq!(tree.share_name, "TestShare");
    }

    /// A reviver that answers each dial with a fresh mock transport, already
    /// loaded with a negotiate + session-setup conversation. Exercises the real
    /// `negotiate` and `Session::setup` paths, unlike the scripted-server
    /// double in `fault_injection_tests`, which is deliberately about the
    /// revival machinery rather than the protocol.
    struct MockReviver {
        session_id: SessionId,
        dialed: std::sync::atomic::AtomicUsize,
        /// Queued behind the negotiate + session-setup conversation, for a
        /// test whose caller does more on the revived connection.
        after_setup: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockReviver {
        fn new(session_id: SessionId) -> Self {
            Self {
                session_id,
                dialed: std::sync::atomic::AtomicUsize::new(0),
                after_setup: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Also answer `responses`, in order, once the revived session is up.
        fn answering_with(session_id: SessionId, responses: Vec<Vec<u8>>) -> Self {
            Self {
                after_setup: std::sync::Mutex::new(responses),
                ..Self::new(session_id)
            }
        }
    }

    #[async_trait::async_trait]
    impl connection::SessionReviver for MockReviver {
        async fn dial(
            &self,
        ) -> Result<(
            Box<dyn crate::transport::TransportSend>,
            Box<dyn crate::transport::TransportReceive>,
        )> {
            self.dialed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mock = Arc::new(MockTransport::new());
            mock.enable_auto_rewrite_msg_id();
            queue_negotiate_and_session(&mock, self.session_id);
            for response in self.after_setup.lock().unwrap().drain(..) {
                mock.queue_response(response);
            }
            Ok((Box::new(mock.clone()), Box::new(mock)))
        }

        async fn reauthenticate(&self, conn: &mut Connection) -> Result<()> {
            conn.negotiate().await?;
            Session::setup(conn, "user", "pass", "").await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn smb_client_reconnect_creates_new_session() {
        let mock = Arc::new(MockTransport::new());
        let original_session_id = SessionId(0x1111);
        let mut client = make_mock_client(&mock, original_session_id).await;
        assert_eq!(client.session().session_id, original_session_id);

        let reviver = Arc::new(MockReviver::new(SessionId(0x2222)));
        client.conn.set_reviver(Some(reviver.clone()));
        client.reconnect().await.unwrap();

        assert_eq!(
            client.session().session_id,
            SessionId(0x2222),
            "the client must adopt the session the revival established, not \
             keep signing with the dead one's keys"
        );
        assert_eq!(reviver.dialed.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// The reason reconnect happens in place: a `Connection` clone taken before
    /// the reconnect keeps working afterwards.
    ///
    /// Consumers hand these clones out everywhere — a `FileWriter` mid-upload,
    /// a `Watcher`, every task in a pipelined transfer. If a reconnect minted a
    /// fresh `Connection` instead, all of them would be permanently dead and
    /// the consumer would have to rebuild the world, which is reporting the
    /// blip rather than surviving it.
    #[tokio::test]
    async fn a_connection_clone_taken_before_a_reconnect_is_alive_after_it() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x1111)).await;
        let held = client.conn.clone();
        assert_eq!(held.generation(), 0);

        client
            .conn
            .set_reviver(Some(Arc::new(MockReviver::new(SessionId(0x2222)))));
        client.reconnect().await.unwrap();

        assert!(
            !held.is_disconnected(),
            "the clone somebody was mid-transfer on must come back with the \
             connection"
        );
        assert_eq!(held.generation(), 1, "and know it is on a new session");
        assert_eq!(held.session_id(), SessionId(0x2222));
    }

    #[tokio::test]
    async fn smb_client_reconnect_renegotiates_params() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x1111)).await;
        let old_server_guid = client.params().unwrap().server_guid;

        client
            .conn
            .set_reviver(Some(Arc::new(MockReviver::new(SessionId(0x2222)))));
        client.reconnect().await.unwrap();

        // Freshly negotiated. The mock answers with the same numbers, but they
        // came from the new socket -- a rebooted server offering a smaller
        // MaxWriteSize would be reflected here, which a `OnceLock` could not do.
        assert!(client.params().is_some());
        assert_eq!(client.params().unwrap().server_guid, old_server_guid);
    }

    /// A reviver that brings up a whole working share: negotiate, session
    /// setup, tree connect, and one compound CREATE+READ+CLOSE ready to serve.
    struct RevivedShare {
        session_id: SessionId,
        tree_id: TreeId,
        contents: Vec<u8>,
        dialed: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl connection::SessionReviver for RevivedShare {
        async fn dial(
            &self,
        ) -> Result<(
            Box<dyn crate::transport::TransportSend>,
            Box<dyn crate::transport::TransportReceive>,
        )> {
            self.dialed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mock = Arc::new(MockTransport::new());
            mock.enable_auto_rewrite_msg_id();
            queue_negotiate_and_session(&mock, self.session_id);
            mock.queue_response(crate::client::test_helpers::build_tree_connect_response(
                self.tree_id,
                ShareType::Disk,
            ));
            mock.queue_response(crate::client::test_helpers::build_compound_response_frame(
                &[
                    crate::client::test_helpers::build_create_response(
                        FileId {
                            persistent: 9,
                            volatile: 9,
                        },
                        self.contents.len() as u64,
                    ),
                    crate::client::test_helpers::build_read_response(self.contents.clone()),
                    crate::client::test_helpers::build_close_response(),
                ],
            ));
            Ok((Box::new(mock.clone()), Box::new(mock)))
        }

        async fn reauthenticate(&self, conn: &mut Connection) -> Result<()> {
            conn.negotiate().await?;
            Session::setup(conn, "user", "pass", "").await?;
            Ok(())
        }
    }

    /// Build a client on a dead connection, armed to reconnect into
    /// `RevivedShare`.
    async fn client_on_a_dead_session(reviver: Arc<RevivedShare>) -> (SmbClient, Tree) {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x1111)).await;
        mock.queue_response(crate::client::test_helpers::build_tree_connect_response(
            TreeId(1),
            ShareType::Disk,
        ));
        let tree = client.connect_share("TestShare").await.unwrap();

        client.config.auto_reconnect = true;
        client.conn.set_reviver(Some(reviver));
        client.conn.mark_dead(); // the NAS went away
        (client, tree)
    }

    /// What `auto_reconnect` buys at the client level: a read that lands on a
    /// dead session comes back anyway, on a new one, with the tree re-connected
    /// underneath the caller's `&mut Tree`.
    #[tokio::test]
    async fn a_read_on_a_dead_session_reconnects_and_returns_the_data() {
        let reviver = Arc::new(RevivedShare {
            session_id: SessionId(0x2222),
            tree_id: TreeId(77),
            contents: b"survived the blip".to_vec(),
            dialed: std::sync::atomic::AtomicUsize::new(0),
        });
        let (mut client, mut tree) = client_on_a_dead_session(reviver.clone()).await;

        let data = tokio::time::timeout(
            Duration::from_secs(10),
            client.read_file_compound(&mut tree, "notes.txt"),
        )
        .await
        .expect("the read hung, which is the bug")
        .expect("auto_reconnect should have recovered this read");

        assert_eq!(data, b"survived the blip");
        assert_eq!(
            reviver.dialed.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one death, one dial"
        );
        assert_eq!(
            tree.tree_id,
            TreeId(77),
            "the caller's tree must be re-established in place -- the old tree \
             id belongs to a session that no longer exists"
        );
        assert_eq!(client.session().session_id, SessionId(0x2222));
    }

    /// The data-safety boundary: a mutating operation is NEVER replayed across
    /// a reconnect.
    ///
    /// A DELETE that died in flight may already have taken effect on the
    /// server. Re-running it after a reconnect turns "it worked" into "not
    /// found" and, worse, could delete a file the user recreated in between.
    /// The library has no way to tell, so it surfaces the error and lets the
    /// caller decide.
    #[tokio::test]
    async fn a_mutating_operation_is_never_replayed_across_a_reconnect() {
        let reviver = Arc::new(RevivedShare {
            session_id: SessionId(0x2222),
            tree_id: TreeId(77),
            contents: Vec::new(),
            dialed: std::sync::atomic::AtomicUsize::new(0),
        });
        let (mut client, mut tree) = client_on_a_dead_session(reviver.clone()).await;

        for (what, outcome) in [
            ("delete", client.delete_file(&mut tree, "x.txt").await.err()),
            ("rename", client.rename(&mut tree, "a", "b").await.err()),
            ("mkdir", client.create_directory(&mut tree, "d").await.err()),
            (
                "write",
                client.write_file(&mut tree, "x.txt", b"data").await.err(),
            ),
        ] {
            assert!(
                outcome.is_some(),
                "{what} on a dead session must fail, not silently re-run"
            );
        }
        assert_eq!(
            reviver.dialed.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing may reconnect-and-replay an operation that could already \
             have taken effect on the server"
        );
    }

    /// `auto_reconnect` is what arms the connection, and it is off by default.
    #[tokio::test]
    async fn auto_reconnect_off_leaves_the_connection_unarmed() {
        let mock = Arc::new(MockTransport::new());
        let client = make_mock_client(&mock, SessionId(1)).await;
        assert!(!client.config().auto_reconnect);
        assert!(
            !client.conn.can_reconnect(),
            "nothing should dial on a consumer's behalf without being asked"
        );
    }

    #[tokio::test]
    async fn smb_client_auto_reconnect_flag_stored() {
        let mock = Arc::new(MockTransport::new());
        mock.enable_auto_rewrite_msg_id();
        queue_negotiate_and_session(mock.as_ref(), SessionId(1));

        let mut conn = Connection::from_transport(
            Box::new(mock.clone()),
            Box::new(mock.clone()),
            "test-server",
        );
        conn.negotiate().await.unwrap();
        let session = Session::setup(&mut conn, "user", "pass", "").await.unwrap();

        let config = ClientConfig {
            addr: "test-server:445".to_string(),
            timeout: Duration::from_secs(5),
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: String::new(),
            auto_reconnect: true,
            compression: true,
            dfs_enabled: true,
            dfs_target_overrides: std::collections::HashMap::new(),
            connect_options: None,
        };

        let client = SmbClient::from_parts(config, conn, session);
        assert!(client.config().auto_reconnect);
    }

    #[tokio::test]
    async fn smb_client_connection_mut_returns_connection() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(1)).await;

        // Verify we can access the connection.
        assert!(client.connection_mut().params().is_some());
    }

    #[tokio::test]
    async fn smb_client_list_shares_delegates_to_shares_module() {
        let mock = Arc::new(MockTransport::new());
        let mut client = make_mock_client(&mock, SessionId(0x5555)).await;

        // Queue the full share listing flow (same as shares module tests).
        // This verifies SmbClient.list_shares() delegates correctly.
        use crate::client::shares::tests::queue_share_listing_responses;
        queue_share_listing_responses(
            &mock,
            &[
                (
                    "Documents",
                    crate::rpc::srvsvc::STYPE_DISKTREE,
                    "Shared docs",
                ),
                (
                    "IPC$",
                    crate::rpc::srvsvc::STYPE_IPC | crate::rpc::srvsvc::STYPE_SPECIAL,
                    "Remote IPC",
                ),
            ],
        );

        let shares = client.list_shares().await.unwrap();

        // Only disk shares returned.
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "Documents");
    }

    /// The host half of an address, for the UNC path and the DFS cache key.
    ///
    /// Every IPv6 form is here because the old `split(':')` got every one of
    /// them wrong (`[::1]:445` → `[`, `fe80::1:445` → `fe80`) while looking
    /// perfectly healthy on IPv4, which is why it survived so long.
    #[test]
    fn a_host_is_read_off_an_address_without_eating_an_ipv6_literal() {
        let cases = [
            // (address, host)
            ("192.168.1.111:445", "192.168.1.111"),
            ("naspolya.local:445", "naspolya.local"),
            ("lgs-net.com:445", "lgs-net.com"),
            // Bracketed: the brackets say where the literal ends, and come off.
            ("[::1]:445", "::1"),
            ("[2001:db8::5]:445", "2001:db8::5"),
            // Bracket-less: the port is what follows the LAST colon, which is
            // how `ToSocketAddrs` reads it, so this agrees with what we dialled.
            ("fe80::1:445", "fe80::1"),
            ("2001:db8::5:445", "2001:db8::5"),
            // No port: nothing to strip.
            ("naspolya.local", "naspolya.local"),
            ("[::1]", "::1"),
        ];
        for (addr, expected) in cases {
            assert_eq!(super::host_of(addr), expected, "host of {addr:?}");
        }
    }

    /// The UNC path and the address share one derivation, so a DFS cache key
    /// and the tree-connect path can't name two different servers.
    #[test]
    fn the_unc_path_and_the_dialled_address_agree_on_the_server() {
        for addr in [
            "192.168.1.111:445",
            "[::1]:445",
            "fe80::1:445",
            "nas.local:445",
        ] {
            let host = super::host_of(addr);
            assert!(
                !host.contains(':') || !host.starts_with('['),
                "a bracket survived into the UNC path for {addr:?}: {host:?}"
            );
            assert!(!host.is_empty(), "empty host for {addr:?}");
            assert_ne!(host, "[", "the bracket-only bug is back for {addr:?}");
        }
    }
}
