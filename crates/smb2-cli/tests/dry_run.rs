//! `--dry-run` has to describe the work and touch nothing.
//!
//! Every case points at a port nothing listens on, so a command that opens a
//! connection fails outright: the test catches a dry run that isn't dry without
//! needing a server. The ones that write locally also assert the file stays
//! missing.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Loopback port 1, where nothing listens: connecting is refused right away.
const DEAD_SHARE: &str = "//127.0.0.1:1/share";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_smb2"))
        .args(args)
        .env_remove("SMB2_USER")
        .env_remove("SMB2_PASS")
        .env_remove("SMB2_PASS_COMMAND")
        .output()
        .expect("running the smb2 binary")
}

fn expect_dry(args: &[&str]) -> String {
    let output = run(args);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "`smb2 {}` should have been a no-op, but it exited {:?}\nstdout: {stdout}\nstderr: {}",
        args.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    stdout
}

/// A file that exists on every checkout, so `put` has something to read.
fn local_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")
}

fn scratch_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("smb2-cli-dry-run-{}-{name}", std::process::id()))
}

#[test]
fn put_plans_the_upload_without_connecting() {
    let source = local_source();
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "put",
        source.to_str().unwrap(),
        &format!("{DEAD_SHARE}/notes.md"),
    ]);
    assert!(
        stdout.contains("//127.0.0.1:1/share/notes.md"),
        "expected the planned destination in {stdout:?}"
    );
}

#[test]
fn put_plans_the_name_it_would_append_to_a_directory_target() {
    let source = local_source();
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "put",
        source.to_str().unwrap(),
        &format!("{DEAD_SHARE}/inbox/"),
    ]);
    assert!(
        stdout.contains("//127.0.0.1:1/share/inbox/README.md"),
        "expected the source's name appended in {stdout:?}"
    );
}

#[test]
fn get_plans_the_download_without_connecting_or_writing() {
    let destination = scratch_path("download");
    let _ = std::fs::remove_file(&destination);
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "get",
        &format!("{DEAD_SHARE}/notes.md"),
        destination.to_str().unwrap(),
    ]);
    assert!(
        stdout.contains(destination.to_str().unwrap()),
        "expected the planned destination in {stdout:?}"
    );
    assert!(
        !destination.exists(),
        "a dry run wrote {}",
        destination.display()
    );
}

#[test]
fn rm_plans_the_deletion_without_connecting() {
    let stdout = expect_dry(&["--guest", "--dry-run", "rm", &format!("{DEAD_SHARE}/junk")]);
    assert!(stdout.contains("rm //127.0.0.1:1/share/junk"), "{stdout:?}");
}

#[test]
fn rmdir_plans_the_removal_without_connecting() {
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "rmdir",
        &format!("{DEAD_SHARE}/empty"),
    ]);
    assert!(
        stdout.contains("rmdir //127.0.0.1:1/share/empty"),
        "{stdout:?}"
    );
}

#[test]
fn mkdir_plans_the_creation_without_connecting() {
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "mkdir",
        "-p",
        &format!("{DEAD_SHARE}/a/b"),
    ]);
    assert!(
        stdout.contains("mkdir //127.0.0.1:1/share/a/b"),
        "{stdout:?}"
    );
}

#[test]
fn mv_plans_the_rename_without_connecting() {
    let stdout = expect_dry(&[
        "--guest",
        "--dry-run",
        "mv",
        &format!("{DEAD_SHARE}/old"),
        &format!("{DEAD_SHARE}/new"),
    ]);
    assert!(
        stdout.contains("mv //127.0.0.1:1/share/old //127.0.0.1:1/share/new"),
        "{stdout:?}"
    );
}
