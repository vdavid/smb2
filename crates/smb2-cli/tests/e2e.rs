//! End-to-end tests: the built binary against a real Samba server.
//!
//! `tests/dry_run.rs` proves the commands that shouldn't connect don't. This
//! file covers the other half, which is the half that can lose data: what
//! `put`, `get`, `mkdir`, `rm`, `rmdir`, and `mv` actually leave on a share.
//! Both bugs this CLI has shipped (`put --dry-run` uploading anyway, and `put`
//! writing a *file* over a directory name) were caught by hand against a live
//! server, because nothing in CI opened a connection.
//!
//! Requires the `smb-auth` fixture (`testuser`/`testpass`, port 10446, share
//! `private`). Every test is `#[ignore]` so `cargo test` stays server-free.
//!
//! ```sh
//! ./crates/smb2/tests/docker/start.sh internal smb-auth
//! cargo test -p smb2-cli --test e2e -- --ignored
//! ./crates/smb2/tests/docker/stop.sh
//! ```
//!
//! **Isolation:** each test owns `cli-e2e/<its own name>/` on the share and
//! wipes it on entry, so the whole file runs in parallel against one container
//! and a re-run never inherits the last run's leftovers. The library is the
//! oracle: setup and verification go through the `smb2` crate directly, so a
//! CLI bug can't hide behind the CLI agreeing with itself.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use smb2::{SmbClient, Tree};

const ADDR: &str = "127.0.0.1:10446";
const SHARE: &str = "private";
const USER: &str = "testuser";
const PASS: &str = "testpass";

/// The directory on the share that holds every test's scratch directory.
const ROOT: &str = "cli-e2e";

/// `-j` for the batch tests: the CLI's own default, so they run the pool the
/// way a user gets it.
///
/// `pool::run` clamps workers to the job count, so a three-path batch opens
/// three connections here. `rm_at_full_pool_width_deletes_every_path` is the
/// one that opens a wide pool.
const POOL_WIDTH: &str = "8";

// ── Running the binary ───────────────────────────────────────────────

/// Runs the built `smb2` binary with credentials in the environment, where a
/// password doesn't reach the process list.
fn smb2(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_smb2"))
        .args(args)
        .env("SMB2_USER", USER)
        .env("SMB2_PASS", PASS)
        .env_remove("SMB2_PASS_COMMAND")
        .output()
        .expect("running the smb2 binary")
}

/// Runs the binary and requires exit 0, returning stdout.
fn ok(args: &[&str]) -> String {
    let output = smb2(args);
    assert!(
        output.status.success(),
        "`smb2 {}` exited {:?}\nstdout: {}\nstderr: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Runs the binary and requires a non-zero exit, returning stderr. Exit codes
/// are a documented contract (`0` worked, `1` anything failed), so a command
/// that fails silently with a zero status is the bug this catches.
fn fails(args: &[&str]) -> String {
    let output = smb2(args);
    assert!(
        !output.status.success(),
        "`smb2 {}` should have failed, but exited 0\nstdout: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "the documented failure code is 1, got {:?}",
        output.status.code()
    );
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ── The share, as the library sees it ────────────────────────────────

/// What's at a path on the share, checked through the library rather than
/// through the CLI's own `stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Missing,
    File,
    Directory,
}

/// The one SMB connection this test binary opens, plus the runtime that drives
/// it. Every test's setup and verification goes through it.
///
/// The runtime is multi-threaded on purpose: the library spawns a receiver, a
/// writer, and a keepalive task per connection, and a test blocks its own
/// thread on `Command::output()` while this connection stays open. On a
/// current-thread runtime that would starve them and the connection would look
/// dead to itself.
struct Server {
    runtime: tokio::runtime::Runtime,
    client: SmbClient,
    tree: Tree,
}

/// The shared connection, opened on first use.
///
/// One connection for the whole binary, rather than one per test: setup and
/// verification are a handful of round trips each, and 30 handshakes would cost
/// more than the work they support. The lock is held only for those round
/// trips, never across a CLI invocation, so tests still overlap where the time
/// actually goes and the suite needs no thread cap.
fn server() -> std::sync::MutexGuard<'static, Server> {
    static SERVER: std::sync::OnceLock<std::sync::Mutex<Server>> = std::sync::OnceLock::new();
    SERVER
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("building a tokio runtime");
            let (client, tree) = runtime.block_on(async {
                let mut client = smb2::connect(ADDR, USER, PASS)
                    .await
                    .expect("connecting to smb-auth; is the fixture running?");
                let tree = client
                    .connect_share(SHARE)
                    .await
                    .expect("connecting to the `private` share");
                (client, tree)
            });
            std::sync::Mutex::new(Server {
                runtime,
                client,
                tree,
            })
        })
        // A test that panics mid-assertion leaves the mutex poisoned but the
        // connection perfectly healthy, and taking the rest of the suite down
        // with it would bury the one real failure under 24 confusing ones.
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Server {
    fn write(&mut self, path: &str, data: &[u8]) {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async {
            client
                .write_file(tree, path, data)
                .await
                .unwrap_or_else(|error| panic!("writing {path}: {error}"));
        });
    }

    fn read(&mut self, path: &str) -> Vec<u8> {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async {
            // Pipelined rather than the compound single READ: the oracle has
            // to be able to read a file bigger than the server's MaxReadSize,
            // which is exactly what the large-transfer tests put there.
            client
                .read_file_pipelined(tree, path)
                .await
                .unwrap_or_else(|error| panic!("reading {path}: {error}"))
        })
    }

    fn mkdir(&mut self, path: &str) {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async {
            client
                .create_directory(tree, path)
                .await
                .unwrap_or_else(|error| panic!("creating {path}: {error}"));
        });
    }

    fn kind(&mut self, path: &str) -> Kind {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async { kind_of(client, tree, path).await })
    }

    /// The names directly inside `path`, sorted, without `.` and `..`.
    fn names(&mut self, path: &str) -> Vec<String> {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async {
            let mut names: Vec<String> = client
                .list_directory(tree, path)
                .await
                .unwrap_or_else(|error| panic!("listing {path}: {error}"))
                .into_iter()
                .map(|entry| entry.name)
                .filter(|name| name != "." && name != "..")
                .collect();
            names.sort();
            names
        })
    }

    /// Empties `path` and everything under it, then recreates it.
    fn reset(&mut self, path: &str) {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async {
            remove_tree(client, tree, path).await;
            // Whichever test gets there first creates the shared root; a
            // collision just means someone else won the race.
            let _ = client.create_directory(tree, ROOT).await;
            client
                .create_directory(tree, path)
                .await
                .unwrap_or_else(|error| panic!("creating {path}: {error}"));
        });
    }

    fn remove(&mut self, path: &str) {
        let Self {
            runtime,
            client,
            tree,
        } = self;
        runtime.block_on(async { remove_tree(client, tree, path).await });
    }
}

/// One test's scratch directory, on the share and locally.
struct Fixture {
    /// `cli-e2e/<test name>`.
    dir: String,
    /// A local scratch directory, created on first use by [`Fixture::local`].
    local: PathBuf,
}

impl Fixture {
    /// Empties and recreates `cli-e2e/<name>` on the share, so a re-run never
    /// inherits the last run's leftovers.
    fn new(name: &str) -> Self {
        let local =
            std::env::temp_dir().join(format!("smb2-cli-e2e-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&local);
        let fixture = Self {
            dir: format!("{ROOT}/{name}"),
            local,
        };
        server().reset(&fixture.dir);
        fixture
    }

    /// Full path of `relative` inside this test's directory. An empty
    /// `relative` names the directory itself.
    fn path(&self, relative: &str) -> String {
        if relative.is_empty() {
            self.dir.clone()
        } else {
            format!("{}/{relative}", self.dir)
        }
    }

    /// The `//host/share/path` string to hand the CLI. A trailing separator in
    /// `relative` survives, since that's what `put` and `get` read as "into
    /// this directory".
    fn target(&self, relative: &str) -> String {
        format!("//{ADDR}/{SHARE}/{}", self.path(relative))
    }

    /// A local scratch directory, created on first use.
    fn local(&self) -> &Path {
        std::fs::create_dir_all(&self.local).expect("creating the local scratch directory");
        &self.local
    }

    fn write(&self, relative: &str, data: &[u8]) {
        server().write(&self.path(relative), data);
    }

    fn read(&self, relative: &str) -> Vec<u8> {
        server().read(&self.path(relative))
    }

    fn mkdir(&self, relative: &str) {
        server().mkdir(&self.path(relative));
    }

    fn kind(&self, relative: &str) -> Kind {
        server().kind(&self.path(relative))
    }

    fn names(&self, relative: &str) -> Vec<String> {
        server().names(&self.path(relative))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.local);
        // Best effort: a panicking test is more useful with its leftovers on
        // the share than with a second panic here.
        server().remove(&self.dir);
    }
}

async fn kind_of(client: &mut SmbClient, tree: &mut Tree, path: &str) -> Kind {
    match client.stat(tree, path).await {
        Ok(info) if info.is_directory => Kind::Directory,
        Ok(_) => Kind::File,
        Err(_) => Kind::Missing,
    }
}

/// Deletes `path` and everything under it, if it's there at all.
async fn remove_tree(client: &mut SmbClient, tree: &mut Tree, path: &str) {
    match kind_of(client, tree, path).await {
        Kind::Missing => {}
        Kind::File => {
            let _ = client.delete_file(tree, path).await;
        }
        Kind::Directory => {
            let entries = client.list_directory(tree, path).await.unwrap_or_default();
            for entry in entries {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                let child = format!("{path}/{}", entry.name);
                Box::pin(remove_tree(client, tree, &child)).await;
            }
            let _ = client.delete_directory(tree, path).await;
        }
    }
}

/// Bytes that compress badly and change at every offset, so a transfer that
/// drops, duplicates, or reorders a chunk can't come out looking right.
/// Generated eight at a time, because the multi-megabyte cases run in a debug
/// build.
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Comfortably past the 8 MB `MaxReadSize` the `smb-auth` fixture negotiates,
/// so a transfer that can only do one READ or one WRITE has to fail here.
const LARGER_THAN_ONE_READ: usize = 9 * 1024 * 1024;

// ── put ──────────────────────────────────────────────────────────────

/// The bug that shipped: `--dry-run` printed the plan and uploaded anyway.
#[test]
#[ignore = "needs the smb-auth container"]
fn put_dry_run_writes_nothing() {
    let share = Fixture::new("put-dry-run");
    let source = share.local().join("notes.txt");
    std::fs::write(&source, b"real bytes").unwrap();

    let stdout = ok(&[
        "--dry-run",
        "put",
        source.to_str().unwrap(),
        &share.target("notes.txt"),
    ]);
    assert!(stdout.contains("notes.txt"), "{stdout:?}");
    assert_eq!(share.kind("notes.txt"), Kind::Missing);
    assert_eq!(share.names(""), Vec::<String>::new());
}

/// The other bug that shipped: a directory target wrote a *file* under the
/// directory's name, which is how a folder disappears.
#[test]
#[ignore = "needs the smb-auth container"]
fn put_lands_inside_a_directory_target() {
    let share = Fixture::new("put-into-directory");
    share.mkdir("inbox");
    let source = share.local().join("photo.jpg");
    std::fs::write(&source, b"jpeg bytes").unwrap();

    // Both spellings mean "inside inbox": the bare name because the server
    // says it's a directory, the trailing slash because the user said so.
    for target in ["inbox", "inbox/"] {
        ok(&["put", source.to_str().unwrap(), &share.target(target)]);
        assert_eq!(share.kind("inbox"), Kind::Directory, "target {target:?}");
        assert_eq!(share.read("inbox/photo.jpg"), b"jpeg bytes");
    }
}

#[test]
#[ignore = "needs the smb-auth container"]
fn put_refuses_a_trailing_slash_on_a_missing_directory() {
    let share = Fixture::new("put-missing-directory");
    let source = share.local().join("photo.jpg");
    std::fs::write(&source, b"jpeg bytes").unwrap();

    let stderr = fails(&["put", source.to_str().unwrap(), &share.target("nope/")]);
    assert!(stderr.contains("doesn't exist"), "{stderr:?}");
    // Nothing named `nope` may appear, as a file least of all.
    assert_eq!(share.kind("nope"), Kind::Missing);
    assert_eq!(share.names(""), Vec::<String>::new());
}

#[test]
#[ignore = "needs the smb-auth container"]
fn put_refuses_a_trailing_slash_on_a_file() {
    let share = Fixture::new("put-slash-on-file");
    share.write("taken.txt", b"do not touch");
    let source = share.local().join("photo.jpg");
    std::fs::write(&source, b"jpeg bytes").unwrap();

    let stderr = fails(&["put", source.to_str().unwrap(), &share.target("taken.txt/")]);
    assert!(stderr.contains("not a directory"), "{stderr:?}");
    assert_eq!(share.read("taken.txt"), b"do not touch");
}

/// The appended name can land on a directory of its own, and that directory
/// has to survive.
#[test]
#[ignore = "needs the smb-auth container"]
fn put_refuses_when_the_appended_name_is_a_directory() {
    let share = Fixture::new("put-appended-collision");
    share.mkdir("inbox");
    share.mkdir("inbox/photo.jpg");
    share.write("inbox/photo.jpg/inner.txt", b"still here");
    let source = share.local().join("photo.jpg");
    std::fs::write(&source, b"jpeg bytes").unwrap();

    let stderr = fails(&["put", source.to_str().unwrap(), &share.target("inbox/")]);
    assert!(stderr.contains("is a directory"), "{stderr:?}");
    assert_eq!(share.kind("inbox/photo.jpg"), Kind::Directory);
    assert_eq!(share.read("inbox/photo.jpg/inner.txt"), b"still here");
}

#[test]
#[ignore = "needs the smb-auth container"]
fn put_writes_an_explicit_destination_name_and_overwrites_a_file() {
    let share = Fixture::new("put-explicit-name");
    let source = share.local().join("photo.jpg");
    std::fs::write(&source, b"first").unwrap();
    ok(&[
        "put",
        source.to_str().unwrap(),
        &share.target("renamed.bin"),
    ]);
    assert_eq!(share.read("renamed.bin"), b"first");
    assert_eq!(share.names(""), vec!["renamed.bin"]);

    // Overwriting a file is allowed; only a directory is off limits. A shorter
    // second write has to truncate, not leave a tail of the first behind.
    std::fs::write(&source, b"2nd").unwrap();
    ok(&[
        "put",
        source.to_str().unwrap(),
        &share.target("renamed.bin"),
    ]);
    assert_eq!(share.read("renamed.bin"), b"2nd");
}

/// Bigger than one write chunk, so the multi-chunk path is what's tested.
#[test]
#[ignore = "needs the smb-auth container"]
fn put_and_get_round_trip_a_multi_chunk_file() {
    let share = Fixture::new("round-trip");
    let data = payload(3 * 1024 * 1024 + 12_345);
    let source = share.local().join("big.bin");
    std::fs::write(&source, &data).unwrap();

    ok(&["put", source.to_str().unwrap(), &share.target("big.bin")]);
    assert_eq!(share.read("big.bin").len(), data.len());
    assert_eq!(share.read("big.bin"), data, "uploaded bytes differ");

    let back = share.local().join("back.bin");
    ok(&["get", &share.target("big.bin"), back.to_str().unwrap()]);
    assert_eq!(
        std::fs::read(&back).unwrap(),
        data,
        "downloaded bytes differ"
    );
}

/// `get` used to fail outright on anything past the server's `MaxReadSize`
/// (8 MB on a stock Samba), because it asked for the whole file in one READ.
/// A 100 MB download is not an exotic case, and neither is the memory a
/// whole-file read costs: `put` sent a 2.35 GB video through this path.
#[test]
#[ignore = "needs the smb-auth container"]
fn get_streams_a_file_larger_than_one_read() {
    let share = Fixture::new("get-large");
    let data = payload(LARGER_THAN_ONE_READ);
    share.write("big.bin", &data);

    let destination = share.local().join("big.bin");
    ok(&[
        "get",
        &share.target("big.bin"),
        destination.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        data,
        "downloaded bytes differ"
    );
}

#[test]
#[ignore = "needs the smb-auth container"]
fn cat_streams_a_file_larger_than_one_read() {
    let share = Fixture::new("cat-large");
    let data = payload(LARGER_THAN_ONE_READ);
    share.write("big.bin", &data);

    let output = smb2(&["cat", &share.target("big.bin")]);
    assert!(
        output.status.success(),
        "cat exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, data);
}

/// The other direction, over the same threshold, so `put`'s streaming path is
/// held to the same byte-for-byte standard.
#[test]
#[ignore = "needs the smb-auth container"]
fn put_streams_a_file_larger_than_one_write() {
    let share = Fixture::new("put-large");
    let data = payload(LARGER_THAN_ONE_READ);
    let source = share.local().join("big.bin");
    std::fs::write(&source, &data).unwrap();

    ok(&["put", source.to_str().unwrap(), &share.target("big.bin")]);
    assert_eq!(share.read("big.bin"), data, "uploaded bytes differ");
}

// ââ mkdir â───────────────────────────────────────────────────────────

#[test]
#[ignore = "needs the smb-auth container"]
fn mkdir_p_is_idempotent_and_creates_nested_directories() {
    let share = Fixture::new("mkdir-p");
    ok(&["mkdir", "-p", &share.target("2026/2026-08-28")]);
    assert_eq!(share.kind("2026"), Kind::Directory);
    assert_eq!(share.kind("2026/2026-08-28"), Kind::Directory);

    // Running it again has to be a clean no-op, which is the whole point of -p.
    ok(&["mkdir", "-p", &share.target("2026/2026-08-28")]);
    assert_eq!(share.kind("2026/2026-08-28"), Kind::Directory);
}

/// Reporting success over a file is what once hid a wrong path until a much
/// later `ls` tripped over it.
#[test]
#[ignore = "needs the smb-auth container"]
fn mkdir_p_fails_over_a_name_held_by_a_file() {
    let share = Fixture::new("mkdir-p-over-file");
    share.write("2026", b"a file, not a year");

    let stderr = fails(&["mkdir", "-p", &share.target("2026/2026-08-28")]);
    assert!(stderr.contains("file"), "{stderr:?}");
    assert_eq!(share.kind("2026"), Kind::File);
    assert_eq!(share.read("2026"), b"a file, not a year");
}

#[test]
#[ignore = "needs the smb-auth container"]
fn plain_mkdir_refuses_a_name_that_is_taken() {
    let share = Fixture::new("mkdir-collision");
    ok(&["mkdir", &share.target("once")]);
    assert_eq!(share.kind("once"), Kind::Directory);

    let stderr = fails(&["mkdir", &share.target("once")]);
    assert!(stderr.contains("already exists"), "{stderr:?}");

    share.write("taken", b"file");
    let stderr = fails(&["mkdir", &share.target("taken")]);
    assert!(stderr.contains("file"), "{stderr:?}");
    assert_eq!(share.kind("taken"), Kind::File);
}

/// Without `-p`, a parent that isn't there is a failure, and the run still
/// creates the paths it can.
#[test]
#[ignore = "needs the smb-auth container"]
fn mkdir_reports_partial_failure_and_exits_non_zero() {
    let share = Fixture::new("mkdir-partial");
    let stderr = fails(&[
        "mkdir",
        &share.target("fine"),
        &share.target("missing-parent/child"),
    ]);
    assert!(stderr.contains("missing-parent/child"), "{stderr:?}");
    assert_eq!(share.kind("fine"), Kind::Directory);
    assert_eq!(share.kind("missing-parent"), Kind::Missing);
}

// ── get and cat ──────────────────────────────────────────────────────

#[test]
#[ignore = "needs the smb-auth container"]
fn get_dry_run_writes_nothing_locally() {
    let share = Fixture::new("get-dry-run");
    share.write("notes.txt", b"remote bytes");
    let destination = share.local().join("notes.txt");

    let stdout = ok(&[
        "--dry-run",
        "get",
        &share.target("notes.txt"),
        destination.to_str().unwrap(),
    ]);
    assert!(stdout.contains("notes.txt"), "{stdout:?}");
    assert!(!destination.exists(), "a dry run wrote {destination:?}");
}

#[test]
#[ignore = "needs the smb-auth container"]
fn get_writes_into_a_local_directory_or_under_an_explicit_name() {
    let share = Fixture::new("get-destinations");
    share.write("notes.txt", b"remote bytes");
    let into = share.local().join("into");
    std::fs::create_dir_all(&into).unwrap();

    ok(&["get", &share.target("notes.txt"), into.to_str().unwrap()]);
    assert_eq!(
        std::fs::read(into.join("notes.txt")).unwrap(),
        b"remote bytes"
    );

    let named = share.local().join("under-a-new-name.txt");
    ok(&["get", &share.target("notes.txt"), named.to_str().unwrap()]);
    assert_eq!(std::fs::read(&named).unwrap(), b"remote bytes");
}

#[test]
#[ignore = "needs the smb-auth container"]
fn cat_prints_the_file_bytes_verbatim() {
    let share = Fixture::new("cat");
    let data = payload(200_000);
    share.write("blob.bin", &data);

    let output = smb2(&["cat", &share.target("blob.bin")]);
    assert!(output.status.success(), "cat exited {:?}", output.status);
    assert_eq!(output.stdout, data);
}

#[test]
#[ignore = "needs the smb-auth container"]
fn realpath_prints_the_name_the_server_stores() {
    let share = Fixture::new("realpath");
    share.mkdir("Photos");
    share.write("Photos/Summer Trip.JPG", b"jpeg");
    let stored = share.target("Photos/Summer Trip.JPG");

    let asked = share.target("PHOTOS/summer trip.jpg");
    assert_eq!(ok(&["realpath", &asked]).trim_end(), stored);

    let json: serde_json::Value =
        serde_json::from_str(&ok(&["--json", "realpath", &asked])).expect("realpath --json");
    assert_eq!(json["target"], stored.as_str());
    assert_eq!(json["path"], share.path("Photos/Summer Trip.JPG").as_str());
    assert_eq!(json["isDirectory"], false);

    let stderr = fails(&["realpath", &share.target("Photos/missing.jpg")]);
    assert!(stderr.contains("missing.jpg"), "stderr: {stderr}");
}

/// A download that fails must not leave anything behind. Streaming made this a
/// live question: the destination is now opened before the bytes arrive, and
/// the first version of it created an empty file for every failed `get`.
#[test]
#[ignore = "needs the smb-auth container"]
fn a_failed_get_writes_nothing_locally() {
    let share = Fixture::new("get-failure");
    let destination = share.local().join("wanted.bin");

    fails(&[
        "get",
        &share.target("no-such-file"),
        destination.to_str().unwrap(),
    ]);
    assert!(
        !destination.exists(),
        "a failed get created {destination:?}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(share.local())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed get left {leftovers:?} behind"
    );
}

/// And it must not damage what's already there. `get` overwrites, so a failure
/// that had already truncated the destination would trade a missing download
/// for a destroyed local file.
#[test]
#[ignore = "needs the smb-auth container"]
fn a_failed_get_leaves_an_existing_file_intact() {
    let share = Fixture::new("get-failure-overwrite");
    let destination = share.local().join("wanted.bin");
    std::fs::write(&destination, b"the copy I already had").unwrap();

    fails(&[
        "get",
        &share.target("no-such-file"),
        destination.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"the copy I already had"
    );
}

// ââ rm, rmdir, and mv â───────────────────────────────────────────────

#[test]
#[ignore = "needs the smb-auth container"]
fn dry_runs_leave_the_share_untouched() {
    let share = Fixture::new("mutating-dry-runs");
    share.write("doomed.txt", b"still here");
    share.mkdir("empty");

    ok(&["--dry-run", "rm", &share.target("doomed.txt")]);
    ok(&["--dry-run", "rmdir", &share.target("empty")]);
    ok(&[
        "--dry-run",
        "mv",
        &share.target("doomed.txt"),
        &share.target("moved.txt"),
    ]);

    assert_eq!(share.read("doomed.txt"), b"still here");
    assert_eq!(share.kind("empty"), Kind::Directory);
    assert_eq!(share.kind("moved.txt"), Kind::Missing);
}

#[test]
#[ignore = "needs the smb-auth container"]
fn rm_and_rmdir_remove_what_they_name() {
    let share = Fixture::new("rm-and-rmdir");
    share.write("a.txt", b"a");
    share.mkdir("gone");

    ok(&["rm", &share.target("a.txt")]);
    assert_eq!(share.kind("a.txt"), Kind::Missing);

    ok(&["rmdir", &share.target("gone")]);
    assert_eq!(share.kind("gone"), Kind::Missing);
}

#[test]
#[ignore = "needs the smb-auth container"]
fn rm_from_file_deletes_a_batch_relative_to_the_target() {
    let share = Fixture::new("rm-from-file");
    for name in ["one.txt", "two.txt", "three.txt"] {
        share.write(name, b"x");
    }
    let list = share.local().join("paths.txt");
    // Blank lines and `#` comments are part of the batch-input contract.
    std::fs::write(&list, "one.txt\n\n# a comment\ntwo.txt\nthree.txt\n").unwrap();

    let stdout = ok(&[
        "rm",
        "-j",
        POOL_WIDTH,
        "--from-file",
        list.to_str().unwrap(),
        &share.target(""),
    ]);
    assert!(stdout.contains("3 of 3"), "{stdout:?}");
    assert_eq!(share.names(""), Vec::<String>::new());
}

/// A batch wide enough to open the pool all the way.
///
/// `-j 16` is the number the CLI's README quotes, and 16 connections opening at
/// once is what used to wedge one of them for 30 s against Samba. Nothing here
/// is about deleting 32 files; it's about opening 16 connections. See
/// `Inner::client_guid` in the library.
#[test]
#[ignore = "needs the smb-auth container"]
fn rm_at_full_pool_width_deletes_every_path() {
    let share = Fixture::new("rm-full-width");
    let names: Vec<String> = (0..32).map(|i| format!("f{i:02}.txt")).collect();
    for name in &names {
        share.write(name, b"x");
    }
    let list = share.local().join("paths.txt");
    std::fs::write(&list, names.join("\n")).unwrap();

    let stdout = ok(&[
        "rm",
        "-j",
        "16",
        "--from-file",
        list.to_str().unwrap(),
        &share.target(""),
    ]);
    assert!(stdout.contains("32 of 32"), "{stdout:?}");
    assert_eq!(share.names(""), Vec::<String>::new());
}

/// A batch reports every bad path and exits non-zero, and the good paths still
/// get done. Guessing how far a run got is exactly what this prevents.
#[test]
#[ignore = "needs the smb-auth container"]
fn rm_finishes_the_batch_and_exits_non_zero_on_a_partial_failure() {
    let share = Fixture::new("rm-partial-failure");
    share.write("real.txt", b"x");
    share.write("also-real.txt", b"x");

    let stderr = fails(&[
        "rm",
        "-j",
        POOL_WIDTH,
        &share.target("real.txt"),
        &share.target("ghost.txt"),
        &share.target("also-real.txt"),
    ]);
    assert!(stderr.contains("ghost.txt"), "{stderr:?}");
    assert!(stderr.contains("1 failed"), "{stderr:?}");
    assert_eq!(share.names(""), Vec::<String>::new());
}

#[test]
#[ignore = "needs the smb-auth container"]
fn mv_renames_one_path_and_a_whole_batch() {
    let share = Fixture::new("mv");
    share.write("old.txt", b"contents");
    ok(&["mv", &share.target("old.txt"), &share.target("new.txt")]);
    assert_eq!(share.kind("old.txt"), Kind::Missing);
    assert_eq!(share.read("new.txt"), b"contents");

    share.write("a.mp4", b"a");
    share.write("b.mp4", b"b");
    let pairs = share.local().join("pairs.tsv");
    std::fs::write(&pairs, "a.mp4\ta.mov\nb.mp4\tb.mov\n").unwrap();
    ok(&[
        "mv",
        "--from-file",
        pairs.to_str().unwrap(),
        &share.target(""),
    ]);
    assert_eq!(share.read("a.mov"), b"a");
    assert_eq!(share.read("b.mov"), b"b");
    assert_eq!(share.kind("a.mp4"), Kind::Missing);
}

#[test]
#[ignore = "needs the smb-auth container"]
fn mv_refuses_to_cross_shares() {
    let share = Fixture::new("mv-cross-share");
    let stderr = fails(&[
        "mv",
        &share.target("a.txt"),
        &format!("//{ADDR}/other/b.txt"),
    ]);
    assert!(stderr.contains("within one share"), "{stderr:?}");
}

// ── JSON, which is the contract ──────────────────────────────────────

/// `--json` keys are a breaking change to touch, so they get asserted by name.
#[test]
#[ignore = "needs the smb-auth container"]
fn ls_json_carries_the_documented_keys() {
    let share = Fixture::new("json-ls");
    share.write("a.txt", b"12345");
    share.mkdir("sub");
    share.write("sub/b.txt", b"1");

    let items: Vec<serde_json::Value> =
        serde_json::from_str(&ok(&["--json", "ls", &share.target("")]))
            .expect("ls --json is not JSON");
    assert_eq!(items.len(), 2, "{items:#?}");

    let file = items
        .iter()
        .find(|item| item["name"] == "a.txt")
        .expect("a.txt missing");
    // `path` is relative to the share root, not to the listed directory, so it
    // can be fed straight back to another command.
    assert_eq!(file["path"], share.path("a.txt"));
    assert_eq!(file["isDirectory"], false);
    assert_eq!(file["size"], 5);
    assert!(file["modified"].is_i64(), "{file:#?}");
    assert!(file["created"].is_i64(), "{file:#?}");

    let directory = items
        .iter()
        .find(|item| item["name"] == "sub")
        .expect("sub missing");
    assert_eq!(directory["isDirectory"], true);

    // `-R` reaches into subdirectories, and `name` stays the bare entry name
    // while `path` carries the whole share-relative path.
    let recursive: Vec<serde_json::Value> =
        serde_json::from_str(&ok(&["--json", "ls", "-R", &share.target("")])).unwrap();
    let nested = recursive
        .iter()
        .find(|item| item["name"] == "b.txt")
        .expect("b.txt missing from the recursive listing");
    assert_eq!(nested["path"], share.path("sub/b.txt"));
}

#[test]
#[ignore = "needs the smb-auth container"]
fn stat_json_carries_the_documented_keys_including_failures() {
    let share = Fixture::new("json-stat");
    share.write("a.txt", b"12345");

    let items: Vec<serde_json::Value> =
        serde_json::from_str(&ok(&["--json", "stat", &share.target("a.txt")])).unwrap();
    let [item] = &items[..] else {
        panic!("expected one item, got {items:#?}")
    };
    assert_eq!(item["isDirectory"], false);
    assert_eq!(item["size"], 5);
    for key in ["path", "modified", "created", "accessed"] {
        assert!(item.get(key).is_some(), "{key} missing from {item:#?}");
    }

    // A failed path still gets a row, carrying `error` instead of the metadata,
    // so a script sees every path it asked about.
    let output = smb2(&[
        "--json",
        "stat",
        &share.target("a.txt"),
        &share.target("ghost.txt"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let items: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("stat --json is not JSON");
    assert_eq!(items.len(), 2, "{items:#?}");
    assert!(items[1]["error"].is_string(), "{items:#?}");
}

#[test]
#[ignore = "needs the smb-auth container"]
fn df_and_shares_json_carry_the_documented_keys() {
    let _share = Fixture::new("json-df");

    let info: serde_json::Value =
        serde_json::from_str(&ok(&["--json", "df", &format!("//{ADDR}/{SHARE}")])).unwrap();
    assert_eq!(info["share"], SHARE);
    for key in [
        "totalBytes",
        "usedBytes",
        "freeBytes",
        "totalFreeBytes",
        "bytesPerSector",
        "sectorsPerUnit",
    ] {
        assert!(
            info[key].is_u64(),
            "{key} missing or not a number in {info:#?}"
        );
    }

    let shares: Vec<serde_json::Value> =
        serde_json::from_str(&ok(&["--json", "shares", ADDR])).unwrap();
    let private = shares
        .iter()
        .find(|item| item["name"] == SHARE)
        .unwrap_or_else(|| panic!("`private` missing from {shares:#?}"));
    assert!(
        private["type"].is_u64() || private["type"].is_string(),
        "{private:#?}"
    );
    assert!(private.get("comment").is_some(), "{private:#?}");
}

// ── Exit codes ───────────────────────────────────────────────────────

/// `0` when everything worked, `1` when anything failed. Read-only commands
/// have to honour it too, not just the batch ones.
#[test]
#[ignore = "needs the smb-auth container"]
fn read_only_commands_exit_non_zero_on_a_bad_path() {
    let share = Fixture::new("exit-codes");
    ok(&["ls", &share.target("")]);
    fails(&["ls", &share.target("no-such-directory")]);
    fails(&["cat", &share.target("no-such-file")]);
    fails(&[
        "get",
        &share.target("no-such-file"),
        share.local().join("never-written").to_str().unwrap(),
    ]);
    fails(&["stat", &share.target("no-such-file")]);
    fails(&["df", &format!("//{ADDR}/no-such-share")]);
}

/// Bad credentials must fail loudly rather than falling back to guest.
#[test]
#[ignore = "needs the smb-auth container"]
fn a_wrong_password_fails() {
    let share = Fixture::new("bad-credentials");
    let output = Command::new(env!("CARGO_BIN_EXE_smb2"))
        .args(["ls", &share.target("")])
        .env("SMB2_USER", USER)
        .env("SMB2_PASS", "not-the-password")
        .output()
        .expect("running the smb2 binary");
    assert_eq!(output.status.code(), Some(1));
}
