//! Running many operations over a pool of SMB connections.
//!
//! The smb2 crate's `*_files` batch methods issue one round trip per item on a
//! single connection, so overlapping work means running several connections at
//! once. Each worker owns its own client and tree, which keeps the whole thing
//! lock-free: jobs are dealt out by index, and results are stitched back into
//! the caller's order at the end.

use anyhow::{Context, Result};
use smb2::types::status::NtStatus;
use smb2::{FileInfo, SmbClient, Tree};

use crate::auth::Credentials;
use crate::remote::{self, RemoteKind};
use crate::target::Target;

/// One unit of work for the pool.
#[derive(Debug, Clone)]
pub enum Job {
    Stat(String),
    Rename {
        from: String,
        to: String,
    },
    DeleteFile(String),
    DeleteDirectory(String),
    CreateDirectory(String),
    /// Create a directory, treating "it's already there" as success, which is
    /// what `mkdir -p` means.
    CreateDirectoryIfMissing(String),
}

/// What a job produced.
#[derive(Debug)]
pub enum Outcome {
    Done,
    Stat(FileInfo),
    Failed(String),
}

impl Outcome {
    pub fn error(&self) -> Option<&str> {
        match self {
            Outcome::Failed(message) => Some(message),
            _ => None,
        }
    }
}

/// Opens `count` independent connections to the target's share.
pub async fn connect_all(
    target: &Target,
    credentials: &Credentials,
    count: usize,
) -> Result<Vec<(SmbClient, Tree)>> {
    let mut connections = Vec::with_capacity(count);
    for index in 0..count {
        connections.push(
            connect_one(target, credentials)
                .await
                .with_context(|| format!("opening connection {} of {count}", index + 1))?,
        );
    }
    Ok(connections)
}

async fn connect_one(target: &Target, credentials: &Credentials) -> Result<(SmbClient, Tree)> {
    let mut client = smb2::connect(&target.addr(), &credentials.username, &credentials.password)
        .await
        .with_context(|| format!("connecting to {}", target.addr()))?;
    let tree = client
        .connect_share(&target.share)
        .await
        .with_context(|| format!("connecting to share {:?}", target.share))?;
    Ok((client, tree))
}

/// Runs every job, spreading them over `concurrency` connections, and returns
/// the outcomes in the order the jobs were given.
///
/// `on_progress` is called with the number of jobs finished so far, so callers
/// can print something during a long run.
pub async fn run(
    target: &Target,
    credentials: &Credentials,
    concurrency: usize,
    jobs: Vec<Job>,
    mut on_progress: impl FnMut(usize, usize),
) -> Result<Vec<Outcome>> {
    if jobs.is_empty() {
        return Ok(vec![]);
    }
    let total = jobs.len();
    let workers = concurrency.clamp(1, total);

    // Deal jobs round-robin so every worker gets a similar slice, keeping the
    // original index alongside so the caller's order survives.
    let mut lanes: Vec<Vec<(usize, Job)>> = vec![Vec::new(); workers];
    for (index, job) in jobs.into_iter().enumerate() {
        lanes[index % workers].push((index, job));
    }

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut handles = Vec::with_capacity(workers);
    for lane in lanes {
        let target = target.clone();
        let credentials = credentials.clone();
        let progress_tx = progress_tx.clone();
        handles.push(tokio::spawn(async move {
            let (mut client, mut tree) = connect_one(&target, &credentials).await?;
            let mut results = Vec::with_capacity(lane.len());
            for (index, job) in lane {
                let outcome = execute(&mut client, &mut tree, &job).await;
                let _ = progress_tx.send(());
                results.push((index, outcome));
            }
            let _ = client.disconnect_share(&tree).await;
            Ok::<_, anyhow::Error>(results)
        }));
    }
    drop(progress_tx);

    let mut finished = 0;
    while progress_rx.recv().await.is_some() {
        finished += 1;
        on_progress(finished, total);
    }

    let mut outcomes: Vec<Option<Outcome>> = (0..total).map(|_| None).collect();
    for handle in handles {
        for (index, outcome) in handle.await.context("worker task panicked")?? {
            outcomes[index] = Some(outcome);
        }
    }
    Ok(outcomes
        .into_iter()
        .map(|outcome| outcome.unwrap_or_else(|| Outcome::Failed("no result".to_string())))
        .collect())
}

async fn execute(client: &mut SmbClient, tree: &mut Tree, job: &Job) -> Outcome {
    match job {
        Job::Stat(path) => match client.stat(tree, path).await {
            Ok(info) => Outcome::Stat(info),
            Err(error) => Outcome::Failed(error.to_string()),
        },
        Job::Rename { from, to } => report(client.rename(tree, from, to).await),
        Job::DeleteFile(path) => report(client.delete_file(tree, path).await),
        Job::DeleteDirectory(path) => report(client.delete_directory(tree, path).await),
        Job::CreateDirectory(path) => create_directory(client, tree, path, false).await,
        Job::CreateDirectoryIfMissing(path) => create_directory(client, tree, path, true).await,
    }
}

/// Creates a directory, asking what holds the name when the server says it's
/// taken.
async fn create_directory(
    client: &mut SmbClient,
    tree: &mut Tree,
    path: &str,
    parents: bool,
) -> Outcome {
    match client.create_directory(tree, path).await {
        Ok(()) => Outcome::Done,
        Err(error) if error.status() == Some(NtStatus::OBJECT_NAME_COLLISION) => {
            // A file and a directory collide with the same status, so telling
            // them apart takes a second round trip. It only happens on a path
            // that has already failed once, so the batch pays nothing for it.
            let occupant = remote::kind(client, tree, path).await.ok();
            match resolve_collision(occupant, parents) {
                Ok(()) => Outcome::Done,
                Err(message) => Outcome::Failed(message),
            }
        }
        Err(error) => Outcome::Failed(error.to_string()),
    }
}

/// What a `mkdir` should make of a name that's already taken. `-p` asked for a
/// directory to be there, so finding one is exactly the point and the job is
/// done; finding a file is not, and calling that success is how a wrong path
/// stays hidden until something else trips over it.
fn resolve_collision(occupant: Option<RemoteKind>, parents: bool) -> Result<(), String> {
    match occupant {
        Some(RemoteKind::Directory) if parents => Ok(()),
        Some(RemoteKind::Directory) => Err("already exists as a directory".to_string()),
        Some(RemoteKind::File) => Err("already exists as a file, not a directory".to_string()),
        // The server said the name is taken, so it is; a follow-up that says
        // otherwise, or that couldn't run, just leaves nothing to add.
        Some(RemoteKind::Missing) | None => Err("already exists".to_string()),
    }
}

fn report(result: smb2::Result<()>) -> Outcome {
    match result {
        Ok(()) => Outcome::Done,
        Err(error) => Outcome::Failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mkdir_p_accepts_a_directory_that_is_already_there() {
        assert_eq!(resolve_collision(Some(RemoteKind::Directory), true), Ok(()));
    }

    #[test]
    fn mkdir_p_refuses_a_name_taken_by_a_file() {
        let message = resolve_collision(Some(RemoteKind::File), true)
            .expect_err("a file where a directory should be has to fail, as GNU mkdir -p does");
        assert!(message.contains("file"), "{message}");
    }

    #[test]
    fn mkdir_p_refuses_a_collision_it_could_not_identify() {
        assert!(resolve_collision(None, true).is_err());
        assert!(resolve_collision(Some(RemoteKind::Missing), true).is_err());
    }

    #[test]
    fn plain_mkdir_refuses_any_name_that_is_taken() {
        for occupant in [RemoteKind::Directory, RemoteKind::File] {
            let message = resolve_collision(Some(occupant), false)
                .expect_err("without -p, an existing name is an error whatever it holds");
            assert!(message.contains("already exists"), "{message}");
        }
    }
}
