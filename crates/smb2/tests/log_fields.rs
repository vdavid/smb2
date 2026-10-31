//! Guard for the logging convention in `AGENTS.md` § "Logging": a log line
//! prints every path, share, name, host, or user as a quoted, keyed field
//! (`path={:?}`), never bare and never positionally in prose.
//!
//! A bare value has no end a reader can find: `deleted path=Summer (Lake
//! House)/a.jpg refused` gives a log parser, a redactor, or a person no way to
//! tell where the name stops, and a hostile name can forge the rest of the
//! line. Debug-quoting escapes `"` and newlines, so the value always ends at
//! the first unescaped quote.
//!
//! This scans the crate's own sources (`src/`, `examples/`, and the CLI's
//! `src/`) for `trace!` .. `error!` invocations and checks each placeholder two
//! ways:
//!
//! - **By key**: a placeholder right after `path=`, `share=`, and the other
//!   keys in [`SENSITIVE`] must be `{:?}`.
//! - **By value**: a placeholder fed a variable or field named like one of
//!   [`SENSITIVE`] must be keyed and `{:?}`, so `"{path} reclaimed"` and
//!   `"deleted {}", path` both fail.
//!
//! It's a lint on names, not a proof: a path held in a variable called `x`
//! slips through. Name variables after what they hold and it catches the rest.

use std::fs;
use std::path::{Path, PathBuf};

/// Keys and variable names that carry a path, share, file name, host, or user.
const SENSITIVE: &[&str] = &[
    // Paths and file names.
    "path",
    "wire_path",
    "stream",
    "wire_name",
    "normalized",
    "unc_path",
    "referral_path",
    "request_path",
    "source_path",
    "dest_path",
    "remaining_path",
    "suffix",
    "from",
    "to",
    "from_normalized",
    "to_normalized",
    "name",
    "file",
    "dir",
    "compose_dir",
    // Shares and DFS namespaces.
    "share",
    "share_name",
    "namespace",
    "prefix",
    "dfs_path_prefix",
    "soonest",
    "target",
    // Hosts.
    "server",
    "primary_server",
    "host",
    "hostname",
    "server_hostname",
    "addr",
    "target_addr",
    "ip",
    // Users.
    "user",
    "username",
    "account",
    "realm",
    "crealm",
    "principal",
    "cname",
    "sname",
];

const LOG_MACROS: &[&str] = &["trace!(", "debug!(", "info!(", "warn!(", "error!("];

fn is_sensitive(word: &str) -> bool {
    SENSITIVE.contains(&word)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Skip a string or char literal starting at `i`, returning the index just
/// past it, or `None` when `i` doesn't start one.
fn skip_literal(b: &[u8], i: usize) -> Option<usize> {
    match b[i] {
        b'"' => {
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'\\' => j += 2,
                    b'"' => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(b.len())
        }
        b'r' if i + 1 < b.len() && (b[i + 1] == b'"' || b[i + 1] == b'#') => {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j >= b.len() || b[j] != b'"' {
                return None;
            }
            j += 1;
            while j < b.len() {
                if b[j] == b'"'
                    && b[j + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&c| c == b'#')
                        .count()
                        == hashes
                {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(b.len())
        }
        // A char literal ('x', '\n', '"'); a lifetime has no closing quote two
        // bytes on and isn't skipped.
        b'\'' => {
            if b.get(i + 1) == Some(&b'\\') {
                let close = b[i + 2..].iter().position(|&c| c == b'\'')?;
                Some(i + 2 + close + 1)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The macro's arguments, split at top-level commas. `start` is just past the
/// opening paren.
fn split_args(src: &str, start: usize) -> Vec<String> {
    let b = src.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut arg_start = start;
    let mut i = start;
    while i < b.len() {
        // Only an identifier can't run into a raw string's `r`.
        let after_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        if !(after_ident && b[i] == b'r') {
            if let Some(next) = skip_literal(b, i) {
                i = next;
                continue;
            }
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => {
                args.push(src[arg_start..i].trim().to_string());
                return args;
            }
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                args.push(src[arg_start..i].trim().to_string());
                arg_start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    args
}

/// A plain string literal's text, with line continuations removed. Other
/// escapes stay as written; nothing here depends on them.
fn literal_text(arg: &str) -> Option<String> {
    let inner = arg.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\n') => {
                    while chars.peek().is_some_and(|c| c.is_whitespace()) {
                        chars.next();
                    }
                }
                Some(&next) => {
                    out.push(c);
                    out.push(next);
                    chars.next();
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// What a value expression is named after: `self.share_name` is
/// `share_name`, `target.server` is `server`, `dir.display()` is `dir`,
/// `self.connections.primary_server()` is `primary_server`.
fn subject(expr: &str) -> String {
    let mut e = expr.trim().trim_start_matches(['&', '*']).to_string();
    for suffix in [".display()", ".as_str()", ".to_string()", ".as_ref()"] {
        while let Some(stripped) = e.strip_suffix(suffix) {
            e = stripped.to_string();
        }
    }
    if let Some(stripped) = e.strip_suffix("()") {
        e = stripped.to_string();
    }
    if let Some(open) = e.find('[') {
        e.truncate(open);
    }
    e.rsplit(['.', ':']).next().unwrap_or("").trim().to_string()
}

/// The `key` of a `key=` directly before byte `at` of `fmt`, if any.
fn key_before(fmt: &str, at: usize) -> Option<&str> {
    let head = fmt[..at].strip_suffix('=')?;
    let start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |p| p + 1);
    let key = &head[start..];
    (!key.is_empty()).then_some(key)
}

/// Every placeholder that breaks the convention, as a reason per offender.
fn violations(args: &[String]) -> Vec<String> {
    // `target: "smb2::x", "fmt", ..` isn't used in this crate; a first argument
    // that isn't a literal is a forwarding macro, which has no format to check.
    let Some(fmt) = args.first().and_then(|a| literal_text(a)) else {
        return Vec::new();
    };
    let named = |name: &str| -> Option<&str> {
        args[1..].iter().find_map(|a| {
            let (lhs, rhs) = a.split_once('=')?;
            (lhs.trim() == name && !rhs.starts_with('=')).then(|| rhs.trim())
        })
    };

    let mut out = Vec::new();
    let mut next_positional = 0usize;
    let bytes = fmt.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' if bytes.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if bytes.get(i + 1) == Some(&b'}') => i += 2,
            b'{' => {
                let Some(len) = fmt[i..].find('}') else { break };
                let inner = &fmt[i + 1..i + len];
                let (arg, spec) = inner.split_once(':').unwrap_or((inner, ""));
                let expr: String = if arg.is_empty() {
                    let e = args.get(1 + next_positional).cloned().unwrap_or_default();
                    next_positional += 1;
                    e
                } else if let Ok(index) = arg.parse::<usize>() {
                    args.get(1 + index).cloned().unwrap_or_default()
                } else {
                    named(arg).unwrap_or(arg).to_string()
                };
                let debug = spec.contains('?');
                let key = key_before(&fmt, i);
                let value = subject(&expr);

                if let Some(key) = key.filter(|k| is_sensitive(k)) {
                    if !debug {
                        out.push(format!("`{key}={{{inner}}}` needs `{{:?}}`"));
                    }
                } else if is_sensitive(&value) && !(key.is_some() && debug) {
                    out.push(format!(
                        "`{{{inner}}}` prints `{expr}` bare; write it as a quoted field, `{value}={{:?}}`"
                    ));
                }
                i += len + 1;
            }
            _ => i += 1,
        }
    }
    out
}

fn scan(file: &Path, root: &Path) -> Vec<String> {
    let src = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
    let mut found = Vec::new();
    for mac in LOG_MACROS {
        for (at, _) in src.match_indices(mac) {
            let line_start = src[..at].rfind('\n').map_or(0, |p| p + 1);
            let line_head = &src[line_start..at];
            if line_head.contains("//") {
                continue;
            }
            // `debug!(` but not `my_debug!(`; `log::debug!(` is fine.
            if src[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let args = split_args(&src, at + mac.len());
            let line = src[..at].matches('\n').count() + 1;
            let rel = file.strip_prefix(root).unwrap_or(file);
            for reason in violations(&args) {
                found.push(format!("{}:{line}: {reason}", rel.display()));
            }
        }
    }
    found
}

#[test]
fn log_lines_print_paths_shares_and_names_as_quoted_fields() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists");
    let mut files = Vec::new();
    for dir in [
        crate_dir.join("src"),
        crate_dir.join("examples"),
        root.join("crates/smb2-cli/src"),
    ] {
        rust_files(&dir, &mut files);
    }
    files.sort();
    assert!(
        files.len() > 50,
        "found only {} source files; is the walk rooted right?",
        files.len()
    );

    let found: Vec<String> = files.iter().flat_map(|f| scan(f, &root)).collect();
    assert!(
        found.is_empty(),
        "{} log placeholder(s) print a path, share, name, host, or user without quoting it. \
         Use a keyed Debug field (`path={{:?}}`, `share={{share_name:?}}`), never `{{}}` or \
         prose (AGENTS.md § Logging):\n{}",
        found.len(),
        found.join("\n")
    );
}

#[test]
fn the_guard_catches_each_shape_it_exists_for() {
    let check = |call: &str| {
        let args = split_args(call, call.find('(').unwrap() + 1);
        violations(&args)
    };
    // A bare keyed value.
    assert_eq!(check(r#"trace!("open path={}", path);"#).len(), 1);
    assert_eq!(
        check(r#"info!("tree: connected share={}, tree_id={}", share_name, id);"#).len(),
        1
    );
    // A positional value in prose, inline or by position.
    assert_eq!(check(r#"info!("durable: {path} reclaimed");"#).len(), 1);
    assert_eq!(
        check(r#"debug!("exclusive delete of {} refused ({:?})", path, status);"#).len(),
        1
    );
    assert_eq!(
        check(r#"debug!("dfs: {share_name:?} is not a share");"#).len(),
        1
    );
    assert_eq!(
        check(r#"debug!("no connection for {}", tree.server);"#).len(),
        1
    );
    // Line continuations and `.display()` don't hide one.
    assert_eq!(
        check("debug!(\"wrote it \\\n     to {}\", dir.display());").len(),
        1
    );

    // The convention passes, including captures, named args, and fields.
    assert!(check(r#"trace!("open path={path:?}");"#).is_empty());
    assert!(check(r#"trace!("open path={:?} offset={}", path, offset);"#).is_empty());
    assert!(check(r#"debug!("server={:?} share={:?}", target.server, target.share);"#).is_empty());
    assert!(check(r#"debug!("renamed from={f:?}", f = from);"#).is_empty());
    assert!(check(r#"debug!("batch, count={}", paths.len());"#).is_empty());
    assert!(check(r#"debug!("{owner} dropped: {e}");"#).is_empty());
    assert!(check(r#"debug!("{{literal}} braces, path={path:?}");"#).is_empty());
}
