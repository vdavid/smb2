//! Commands that change the share: `mkdir`, `rm`, `rmdir`, and `mv`.

use anyhow::Result;

use crate::auth::Credentials;
use crate::batch;
use crate::pool::{self, Job, Outcome};
use crate::target::Target;

/// How a batch of jobs finished, so every command reports the same way.
struct Report {
    total: usize,
    /// Paths that needed nothing done (a `mkdir -p` over an existing
    /// directory). They succeeded, but counting them as created would claim
    /// work that never happened.
    already_there: usize,
    failed: Vec<(String, String)>,
}

impl Report {
    fn summary(&self, verb: &str) -> String {
        let total = self.total;
        let already_there = self.already_there;
        let changed = total - self.failed.len() - already_there;
        if already_there == 0 {
            format!("{verb} {changed} of {total} paths.")
        } else if already_there == total {
            format!("Nothing to create: all {total} paths already existed.")
        } else {
            format!("{verb} {changed} of {total} paths; {already_there} already existed.")
        }
    }

    fn print(&self, verb: &str, dry_run: bool) -> Result<()> {
        if dry_run {
            let succeeded = self.total - self.failed.len();
            println!("Would have {verb} {succeeded} of {} paths.", self.total);
            return Ok(());
        }
        println!("{}", self.summary(verb));
        if !self.failed.is_empty() {
            eprintln!("\n{} failed:", self.failed.len());
            for (path, message) in self.failed.iter().take(50) {
                eprintln!("  {path}: {message}");
            }
            if self.failed.len() > 50 {
                eprintln!("  ... and {} more.", self.failed.len() - 50);
            }
            anyhow::bail!("{} of {} paths failed", self.failed.len(), self.total);
        }
        Ok(())
    }
}

async fn run_jobs(
    base: &Target,
    credentials: &Credentials,
    concurrency: usize,
    paths: Vec<String>,
    jobs: Vec<Job>,
    quiet: bool,
) -> Result<Report> {
    let total = jobs.len();
    let outcomes = pool::run(base, credentials, concurrency, jobs, |done, total| {
        if !quiet && total >= 500 && done % 250 == 0 {
            eprintln!("  {done}/{total}");
        }
    })
    .await?;

    let mut already_there = 0;
    let mut failed = Vec::new();
    for (path, outcome) in paths.into_iter().zip(outcomes) {
        match outcome {
            Outcome::Failed(message) => failed.push((path, message)),
            Outcome::AlreadyThere => already_there += 1,
            Outcome::Done | Outcome::Stat(_) | Outcome::Xattrs(_) => {}
        }
    }
    Ok(Report {
        total,
        already_there,
        failed,
    })
}

pub async fn mkdir(
    targets: &[String],
    input: &batch::BatchInput,
    credentials: &Credentials,
    concurrency: usize,
    parents: bool,
    dry_run: bool,
) -> Result<()> {
    let (base, paths) = input.collect(targets)?;
    let paths = if parents {
        with_ancestors(&paths)
    } else {
        paths
    };
    if dry_run {
        for path in &paths {
            println!("mkdir {}", base.with_path(path).display());
        }
        return Report {
            total: paths.len(),
            already_there: 0,
            failed: vec![],
        }
        .print("created", true);
    }
    // With `-p`, a directory that already exists is fine, and parents have to
    // exist before their children, so it runs one at a time.
    let (jobs, concurrency): (Vec<Job>, usize) = if parents {
        (
            paths
                .iter()
                .cloned()
                .map(Job::CreateDirectoryIfMissing)
                .collect(),
            1,
        )
    } else {
        (
            paths.iter().cloned().map(Job::CreateDirectory).collect(),
            concurrency,
        )
    };
    run_jobs(&base, credentials, concurrency, paths, jobs, false)
        .await?
        .print("Created", false)
}

/// Every ancestor of every path, shallowest first, without duplicates.
fn with_ancestors(paths: &[String]) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    for path in paths {
        let mut prefix = String::new();
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            if !all.contains(&prefix) {
                all.push(prefix.clone());
            }
        }
    }
    all
}

pub async fn rm(
    targets: &[String],
    input: &batch::BatchInput,
    credentials: &Credentials,
    concurrency: usize,
    dry_run: bool,
) -> Result<()> {
    let (base, paths) = input.collect(targets)?;
    if dry_run {
        for path in &paths {
            println!("rm {}", base.with_path(path).display());
        }
        return Report {
            total: paths.len(),
            already_there: 0,
            failed: vec![],
        }
        .print("deleted", true);
    }
    let jobs = paths.iter().cloned().map(Job::DeleteFile).collect();
    run_jobs(&base, credentials, concurrency, paths, jobs, false)
        .await?
        .print("Deleted", false)
}

pub async fn rmdir(
    targets: &[String],
    input: &batch::BatchInput,
    credentials: &Credentials,
    concurrency: usize,
    dry_run: bool,
) -> Result<()> {
    let (base, paths) = input.collect(targets)?;
    if dry_run {
        for path in &paths {
            println!("rmdir {}", base.with_path(path).display());
        }
        return Report {
            total: paths.len(),
            already_there: 0,
            failed: vec![],
        }
        .print("removed", true);
    }
    let jobs = paths.iter().cloned().map(Job::DeleteDirectory).collect();
    run_jobs(&base, credentials, concurrency, paths, jobs, false)
        .await?
        .print("Removed", false)
}

pub async fn mv(
    targets: &[String],
    from_file: Option<&str>,
    replace: bool,
    credentials: &Credentials,
    concurrency: usize,
    dry_run: bool,
) -> Result<()> {
    let (base, pairs) = match from_file {
        Some(source) => {
            let [raw_base] = targets else {
                anyhow::bail!("--from-file needs exactly one target to resolve paths against");
            };
            let base = Target::parse(raw_base)?;
            let mut pairs = Vec::new();
            for (from, to) in batch::read_pairs(source)? {
                pairs.push((base.resolve(&from)?.path, base.resolve(&to)?.path));
            }
            (base.with_path(""), pairs)
        }
        None => {
            let [from, to] = targets else {
                anyhow::bail!("mv takes a source and a destination, or --from-file");
            };
            let from = Target::parse(from)?;
            let to = Target::parse(to)?;
            if from.host != to.host || from.share != to.share {
                anyhow::bail!("mv works within one share; copy across shares with get and put");
            }
            let pairs = vec![(from.path.clone(), to.path)];
            (from.with_path(""), pairs)
        }
    };

    if dry_run {
        for (from, to) in &pairs {
            println!(
                "mv {}{} {}",
                if replace { "--replace " } else { "" },
                base.with_path(from).display(),
                base.with_path(to).display()
            );
        }
        return Report {
            total: pairs.len(),
            already_there: 0,
            failed: vec![],
        }
        .print("moved", true);
    }

    let paths: Vec<String> = pairs.iter().map(|(from, _)| from.clone()).collect();
    let jobs = pairs
        .into_iter()
        .map(|(from, to)| Job::Rename { from, to, replace })
        .collect();
    run_jobs(&base, credentials, concurrency, paths, jobs, false)
        .await?
        .print("Moved", false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ancestors_shallowest_first() {
        let expanded =
            with_ancestors(&["2026/2026-08-05".to_string(), "2026/2026-08-06".to_string()]);
        assert_eq!(expanded, vec!["2026", "2026/2026-08-05", "2026/2026-08-06"]);
    }

    fn report(total: usize, already_there: usize, failed: usize) -> Report {
        Report {
            total,
            already_there,
            failed: (0..failed)
                .map(|index| (format!("path-{index}"), "no".to_string()))
                .collect(),
        }
    }

    #[test]
    fn summary_counts_only_what_was_created() {
        assert_eq!(report(4, 0, 0).summary("Created"), "Created 4 of 4 paths.");
        assert_eq!(
            report(4, 3, 0).summary("Created"),
            "Created 1 of 4 paths; 3 already existed."
        );
        assert_eq!(
            report(4, 2, 1).summary("Created"),
            "Created 1 of 4 paths; 2 already existed."
        );
    }

    #[test]
    fn summary_says_so_when_everything_was_already_there() {
        assert_eq!(
            report(4, 4, 0).summary("Created"),
            "Nothing to create: all 4 paths already existed."
        );
    }
}
