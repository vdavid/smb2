//! Native (OS-mounted) SMB operations -- uses std::fs on the mounted share path.

use crate::config::Target;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Create the test directory on the native mount. Returns the path.
/// Uses a unique subdir per cycle to avoid SMB cache staleness issues.
pub fn setup(target: &Target, cycle_id: &str) -> std::io::Result<PathBuf> {
    let dir = target.native_test_base().join(cycle_id);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Upload `count` files of `size` bytes each. Returns elapsed time.
pub fn upload(dir: &PathBuf, count: usize, size: usize, data: &[u8]) -> Duration {
    let start = Instant::now();
    for i in 0..count {
        let path = dir.join(format!("bench_{i:05}.dat"));
        let mut f = fs::File::create(&path).expect("create file");
        f.write_all(&data[..size]).expect("write file");
    }
    start.elapsed()
}

/// List the directory and return (count, elapsed).
/// Filters out macOS metadata files (.DS_Store, ._ resource forks).
pub fn list(dir: &PathBuf) -> (usize, Duration) {
    let start = Instant::now();
    let count = fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            !name.starts_with("._") && name != ".DS_Store"
        })
        .count();
    (count, start.elapsed())
}

/// Download all files to a local temp dir. Returns (bytes, elapsed).
pub fn download(dir: &PathBuf, local_dest: &PathBuf) -> (u64, Duration) {
    use std::io::Read;
    #[cfg(target_os = "macos")]
    use std::os::unix::io::AsRawFd;

    fs::create_dir_all(local_dest).expect("create local dest");
    let start = Instant::now();
    let mut total_bytes = 0u64;
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let src = entry.path();
        let dst = local_dest.join(entry.file_name());

        // Open with F_NOCACHE to bypass macOS kernel page cache.
        // Without this, warm reads hit the cache and show artificially
        // fast times that no userspace SMB client can match.
        let mut src_file = fs::File::open(&src).expect("open src");
        #[cfg(target_os = "macos")]
        unsafe {
            libc::fcntl(src_file.as_raw_fd(), libc::F_NOCACHE, 1);
        }

        let mut dst_file = fs::File::create(&dst).expect("create dst");
        let mut buf = vec![0u8; 1024 * 1024]; // 1 MB read buffer
        loop {
            let n = src_file.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            dst_file.write_all(&buf[..n]).expect("write");
            total_bytes += n as u64;
        }
    }
    (total_bytes, start.elapsed())
}

/// Delete all files and the test directory. Returns elapsed time.
pub fn delete(dir: &PathBuf) -> Duration {
    let start = Instant::now();
    // Use remove_dir_all for robustness on SMB mounts (avoids stale cache entries)
    fs::remove_dir_all(dir).expect("remove_dir_all");
    start.elapsed()
}

/// Remove test base directory if it exists (for --cleanup-only).
pub async fn cleanup(target: &Target) {
    let dir = target.native_test_base();
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
        println!("  Removed {}", dir.display());
    } else {
        println!("  {} doesn't exist, nothing to clean", dir.display());
    }
}
