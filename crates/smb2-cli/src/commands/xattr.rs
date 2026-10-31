//! `xattr`, mirroring macOS's own command, and `streams`, the raw stream list.

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::auth::Credentials;
use crate::batch;
use crate::output;
use crate::pool::{self, Job, Outcome};
use crate::target::Target;

/// What `smb2 xattr` was asked to do, from its flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No flag: each path's attribute names.
    Names,
    /// `-l`: names and values.
    List,
    /// `-p NAME`: one value.
    Print(String),
    /// `-w NAME VALUE`.
    Write(String, Vec<u8>),
    /// `-d NAME`.
    Delete(String),
}

impl Action {
    /// Reads the flags, which clap has already kept to one of the actions.
    pub fn from_flags(
        list: bool,
        print: Option<&String>,
        write: Option<&Vec<String>>,
        delete: Option<&String>,
        hex: bool,
    ) -> Result<Self> {
        if let Some(name) = print {
            return Ok(Action::Print(name.clone()));
        }
        if let Some(name) = delete {
            return Ok(Action::Delete(name.clone()));
        }
        if let Some([name, value]) = write.map(Vec::as_slice) {
            let value = if hex {
                parse_hex(value)?
            } else {
                value.as_bytes().to_vec()
            };
            return Ok(Action::Write(name.clone(), value));
        }
        Ok(if list { Action::List } else { Action::Names })
    }
}

/// Hex digits to bytes. Whitespace may separate them, the way macOS's `xattr
/// -px` prints them.
fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let digits: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        bail!("hex value has an odd number of digits");
    }
    digits
        .chunks(2)
        .map(|pair| {
            let pair: String = pair.iter().collect();
            u8::from_str_radix(&pair, 16).with_context(|| format!("{pair:?} isn't a hex byte"))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A value for a person: as text when it's valid UTF-8 with nothing unprintable,
/// and hex otherwise, as macOS's `xattr` does.
fn display_value(bytes: &[u8], hex: bool) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) if !hex && !text.chars().any(char::is_control) => text.to_string(),
        _ => to_hex(bytes),
    }
}

pub struct Options {
    pub concurrency: usize,
    pub hex: bool,
    pub as_json: bool,
    pub dry_run: bool,
}

pub async fn xattr(
    targets: &[String],
    input: &batch::BatchInput,
    credentials: &Credentials,
    action: Action,
    options: Options,
) -> Result<()> {
    let (base, paths) = input.collect(targets)?;

    // Reads have nothing to preview, and ignore --dry-run like every read-only
    // command does.
    if options.dry_run {
        let verb = match &action {
            Action::Write(name, value) => Some(format!("xattr -w {name} ({} bytes)", value.len())),
            Action::Delete(name) => Some(format!("xattr -d {name}")),
            _ => None,
        };
        if let Some(verb) = verb {
            for path in &paths {
                println!("{verb} {}", base.with_path(path).display());
            }
            println!("Would have changed {} paths.", paths.len());
            return Ok(());
        }
    }

    let jobs: Vec<Job> = paths
        .iter()
        .map(|path| {
            let path = path.clone();
            match &action {
                Action::Names => Job::XattrNames(path),
                Action::List => Job::XattrList(path),
                Action::Print(name) => Job::XattrGet {
                    path,
                    name: name.clone(),
                },
                Action::Write(name, value) => Job::XattrSet {
                    path,
                    name: name.clone(),
                    value: value.clone(),
                },
                Action::Delete(name) => Job::XattrRemove {
                    path,
                    name: name.clone(),
                },
            }
        })
        .collect();
    let outcomes = pool::run(&base, credentials, options.concurrency, jobs, |_, _| {}).await?;

    let many = paths.len() > 1;
    let mut failures = Vec::new();
    let mut items = Vec::new();
    for (path, outcome) in paths.iter().zip(&outcomes) {
        match outcome {
            Outcome::Xattrs(attributes) => {
                if options.as_json {
                    let attributes: Vec<_> = attributes
                        .iter()
                        .map(|(name, value)| {
                            json!({
                                "name": name,
                                "valueHex": value.as_deref().map(to_hex),
                            })
                        })
                        .collect();
                    items.push(json!({ "path": path, "attributes": attributes }));
                } else {
                    print_attributes(path, attributes, many, &action, options.hex);
                }
            }
            Outcome::Done => {
                if options.as_json {
                    items.push(json!({ "path": path, "ok": true }));
                }
            }
            Outcome::Failed(message) => failures.push((path, message.clone())),
            Outcome::AlreadyThere | Outcome::Stat(_) => {}
        }
    }
    if options.as_json {
        println!("{}", serde_json::to_string_pretty(&items)?);
    }
    report_failures(&failures, paths.len())
}

fn print_attributes(
    path: &str,
    attributes: &[(String, Option<Vec<u8>>)],
    many: bool,
    action: &Action,
    hex: bool,
) {
    let prefix = if many {
        format!("{path}: ")
    } else {
        String::new()
    };
    for (name, value) in attributes {
        match (action, value) {
            (Action::Print(_), Some(value)) => {
                println!("{prefix}{}", display_value(value, hex));
            }
            (_, Some(value)) => println!("{prefix}{name}: {}", display_value(value, hex)),
            (_, None) => println!("{prefix}{name}"),
        }
    }
}

fn report_failures(failures: &[(&String, String)], total: usize) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    eprintln!("{} failed:", failures.len());
    for (path, message) in failures.iter().take(50) {
        eprintln!("  {path}: {message}");
    }
    if failures.len() > 50 {
        eprintln!("  ... and {} more.", failures.len() - 50);
    }
    bail!("{} of {total} paths failed", failures.len());
}

/// List a path's named streams.
pub async fn streams(target: &Target, credentials: &Credentials, as_json: bool) -> Result<()> {
    let (mut client, mut tree) = pool::connect_all(target, credentials, 1)
        .await?
        .pop()
        .expect("connect_all returns one connection");
    let listed = client.list_streams(&mut tree, &target.path).await;
    let _ = client.disconnect_share(&tree).await;
    let listed = listed.with_context(|| format!("listing streams of {}", target.display()))?;

    if as_json {
        let items: Vec<_> = listed
            .iter()
            .map(|stream| {
                json!({
                    "name": stream.name,
                    "size": stream.size,
                    "allocationSize": stream.allocation_size,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for stream in &listed {
            println!("{:>12}  {}", output::bytes(stream.size), stream.name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_takes_what_macos_prints() {
        assert_eq!(parse_hex("00 ff\n0A").unwrap(), [0, 0xFF, 0x0A]);
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn a_value_shows_as_text_only_when_it_reads_as_text() {
        assert_eq!(display_value(b"hello", false), "hello");
        assert_eq!(display_value(b"hello", true), "68656c6c6f");
        assert_eq!(display_value(&[0xFF, 0x00], false), "ff00");
        assert_eq!(display_value(b"two\nlines", false), "74776f0a6c696e6573");
    }

    #[test]
    fn the_flags_pick_one_action() {
        let name = "user.a".to_string();
        let write = vec!["user.a".to_string(), "6869".to_string()];
        assert_eq!(
            Action::from_flags(false, None, None, None, false).unwrap(),
            Action::Names
        );
        assert_eq!(
            Action::from_flags(true, None, None, None, false).unwrap(),
            Action::List
        );
        assert_eq!(
            Action::from_flags(false, Some(&name), None, None, false).unwrap(),
            Action::Print(name.clone())
        );
        assert_eq!(
            Action::from_flags(false, None, None, Some(&name), false).unwrap(),
            Action::Delete(name.clone())
        );
        assert_eq!(
            Action::from_flags(false, None, Some(&write), None, true).unwrap(),
            Action::Write(name.clone(), b"hi".to_vec())
        );
        assert_eq!(
            Action::from_flags(false, None, Some(&write), None, false).unwrap(),
            Action::Write(name, b"6869".to_vec())
        );
    }
}
