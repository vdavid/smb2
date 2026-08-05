//! Collecting the list of paths a batch command should work on.
//!
//! Paths can come from the command line or, for big jobs, from a file or
//! stdin where each line is a path relative to a base target. Everything in
//! one invocation has to live on the same host and share, since a batch runs
//! over one pool of connections.

use std::io::Read;

use anyhow::{bail, Context, Result};

use crate::target::Target;

/// Where the paths for a batch come from.
#[derive(Debug, Clone, clap::Args)]
pub struct BatchInput {
    /// Read paths from this file, one per line, relative to the target.
    /// Use `-` for stdin.
    #[arg(long, value_name = "FILE")]
    pub from_file: Option<String>,
}

impl BatchInput {
    /// Turns command-line targets plus any file input into one share and a
    /// list of paths inside it.
    pub fn collect(&self, targets: &[String]) -> Result<(Target, Vec<String>)> {
        match &self.from_file {
            Some(source) => {
                let [base] = targets else {
                    bail!("--from-file needs exactly one target to resolve paths against");
                };
                let base = Target::parse(base)?;
                let mut paths = Vec::new();
                for line in read_lines(source)? {
                    let resolved = base.resolve(&line)?;
                    ensure_same_share(&base, &resolved)?;
                    paths.push(resolved.path);
                }
                Ok((base.with_path(""), paths))
            }
            None => {
                if targets.is_empty() {
                    bail!("no targets given");
                }
                let first = Target::parse(&targets[0])?;
                let mut paths = Vec::with_capacity(targets.len());
                for raw in targets {
                    let target = Target::parse(raw)?;
                    ensure_same_share(&first, &target)?;
                    paths.push(target.path);
                }
                Ok((first.with_path(""), paths))
            }
        }
    }
}

fn ensure_same_share(base: &Target, other: &Target) -> Result<()> {
    if base.host != other.host || base.port != other.port || base.share != other.share {
        bail!(
            "all paths must be on one share: {} and {} differ",
            base.with_path("").display(),
            other.with_path("").display()
        );
    }
    Ok(())
}

/// Reads non-empty, non-comment lines from a file or stdin.
pub fn read_lines(source: &str) -> Result<Vec<String>> {
    let contents = if source == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("reading paths from stdin")?;
        buffer
    } else {
        std::fs::read_to_string(source).with_context(|| format!("reading {source}"))?
    };
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Reads `from<TAB>to` pairs for a batch rename.
pub fn read_pairs(source: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (number, line) in read_lines(source)?.into_iter().enumerate() {
        let Some((from, to)) = line.split_once('\t') else {
            bail!(
                "line {} of {source} is not `from<TAB>to`: {line:?}",
                number + 1
            );
        };
        pairs.push((from.trim().to_string(), to.trim().to_string()));
    }
    Ok(pairs)
}
