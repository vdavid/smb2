//! `smb2`: a command-line SMB2/3 client that talks to a share directly,
//! without mounting it.

mod auth;
mod batch;
mod commands;
mod output;
mod pool;
mod target;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::auth::AuthArgs;
use crate::target::Target;

#[derive(Parser)]
#[command(
    name = "smb2",
    version,
    about = "List, move, and delete files on an SMB share without mounting it",
    after_help = "Targets look like //host/share/path. Passwords come from --password-command, \
                  SMB2_PASS, or a prompt."
)]
struct Cli {
    #[command(flatten)]
    auth: AuthArgs,

    /// How many connections to spread batch work over.
    #[arg(short = 'j', long, default_value_t = 8, global = true)]
    concurrency: usize,

    /// Print machine-readable JSON instead of text.
    #[arg(long, global = true)]
    json: bool,

    /// Show what would happen without changing anything.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List a directory.
    Ls {
        /// Target like //host/share/path.
        target: String,
        /// Show size and modification time.
        #[arg(short = 'l', long)]
        long: bool,
        /// Descend into subdirectories.
        #[arg(short = 'R', long)]
        recursive: bool,
    },
    /// Show metadata for one or more paths.
    Stat {
        /// Targets like //host/share/path.
        targets: Vec<String>,
        #[command(flatten)]
        input: batch::BatchInput,
    },
    /// Create directories.
    Mkdir {
        targets: Vec<String>,
        #[command(flatten)]
        input: batch::BatchInput,
        /// Create missing parent directories too.
        #[arg(short = 'p', long)]
        parents: bool,
    },
    /// Delete files.
    Rm {
        targets: Vec<String>,
        #[command(flatten)]
        input: batch::BatchInput,
    },
    /// Remove empty directories.
    Rmdir {
        targets: Vec<String>,
        #[command(flatten)]
        input: batch::BatchInput,
    },
    /// Move or rename within one share.
    Mv {
        /// Source and destination, or one base target with --from-file.
        targets: Vec<String>,
        /// Read `from<TAB>to` pairs from this file, or `-` for stdin.
        #[arg(long, value_name = "FILE")]
        from_file: Option<String>,
    },
    /// Print a file to stdout.
    Cat { target: String },
    /// Download a file.
    Get {
        target: String,
        /// Local destination; defaults to the file's name here.
        destination: Option<String>,
    },
    /// Upload a file.
    Put {
        source: PathBuf,
        /// Target like //host/share/path.
        target: String,
    },
    /// Show free space on a share.
    Df { target: String },
    /// List the shares a server offers.
    Shares {
        /// Host, or a target like //host.
        host: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let credentials = cli.auth.resolve()?;
    let concurrency = cli.concurrency.max(1);

    match &cli.command {
        Commands::Ls {
            target,
            long,
            recursive,
        } => {
            let target = Target::parse(target)?;
            commands::meta::ls(&target, &credentials, *long, *recursive, cli.json).await
        }
        Commands::Stat { targets, input } => {
            let (base, paths) = input.collect(targets)?;
            commands::meta::stat(&base, &credentials, paths, concurrency, cli.json).await
        }
        Commands::Mkdir {
            targets,
            input,
            parents,
        } => {
            commands::mutate::mkdir(
                targets,
                input,
                &credentials,
                concurrency,
                *parents,
                cli.dry_run,
            )
            .await
        }
        Commands::Rm { targets, input } => {
            commands::mutate::rm(targets, input, &credentials, concurrency, cli.dry_run).await
        }
        Commands::Rmdir { targets, input } => {
            commands::mutate::rmdir(targets, input, &credentials, concurrency, cli.dry_run).await
        }
        Commands::Mv { targets, from_file } => {
            commands::mutate::mv(
                targets,
                from_file.as_deref(),
                &credentials,
                concurrency,
                cli.dry_run,
            )
            .await
        }
        Commands::Cat { target } => {
            commands::transfer::cat(&Target::parse(target)?, &credentials).await
        }
        Commands::Get {
            target,
            destination,
        } => {
            commands::transfer::get(
                &Target::parse(target)?,
                &credentials,
                destination.as_deref(),
                cli.dry_run,
            )
            .await
        }
        Commands::Put { source, target } => {
            commands::transfer::put(source, &Target::parse(target)?, &credentials, cli.dry_run)
                .await
        }
        Commands::Df { target } => {
            commands::meta::df(&Target::parse(target)?, &credentials, cli.json).await
        }
        Commands::Shares { host } => {
            let (host, port) = parse_host(host);
            commands::meta::shares(&host, port, &credentials, cli.json).await
        }
    }
}

/// Accepts a bare host, `host:port`, or a `//host` target.
fn parse_host(input: &str) -> (String, u16) {
    let trimmed = input
        .trim_start_matches("smb://")
        .trim_start_matches("//")
        .trim_end_matches('/');
    match trimmed.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(445)),
        None => (trimmed.to_string(), 445),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_the_cli_definition() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_host_forms() {
        assert_eq!(parse_host("raspi"), ("raspi".to_string(), 445));
        assert_eq!(parse_host("//raspi/"), ("raspi".to_string(), 445));
        assert_eq!(parse_host("raspi:4450"), ("raspi".to_string(), 4450));
    }
}
