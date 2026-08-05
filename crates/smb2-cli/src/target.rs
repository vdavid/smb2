//! Parsing of SMB targets like `//host/share/path`.

use anyhow::{bail, Result};

/// A location on an SMB server: which host, which share, and which path
/// inside that share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub share: String,
    /// Path inside the share, with `/` separators and no leading slash.
    /// Empty means the share root.
    pub path: String,
}

impl Target {
    /// Parses `smb://host[:port]/share[/path]`, `//host[:port]/share[/path]`,
    /// or the Windows form `\\host\share\path`.
    pub fn parse(input: &str) -> Result<Self> {
        let normalized = input.replace('\\', "/");
        let rest = normalized
            .strip_prefix("smb://")
            .or_else(|| normalized.strip_prefix("//"))
            .ok_or_else(|| {
                anyhow::anyhow!("target must look like //host/share/path, got {input:?}")
            })?;

        let (authority, remainder) = match rest.split_once('/') {
            Some((authority, remainder)) => (authority, remainder),
            None => bail!("target {input:?} names a host but no share"),
        };
        if authority.is_empty() {
            bail!("target {input:?} has an empty host");
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().unwrap_or(445)),
            None => (authority.to_string(), 445),
        };

        let (share, path) = match remainder.split_once('/') {
            Some((share, path)) => (share, path),
            None => (remainder, ""),
        };
        if share.is_empty() {
            bail!("target {input:?} has an empty share name");
        }

        Ok(Self {
            host,
            port,
            share: share.to_string(),
            path: trim_path(path),
        })
    }

    /// The `host:port` string the smb2 crate wants.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The same location with a different path inside the share.
    pub fn with_path(&self, path: &str) -> Self {
        Self {
            path: trim_path(path),
            ..self.clone()
        }
    }

    /// Resolves a path that may be absolute (`//host/share/x`) or relative to
    /// this target's path. Used for batch inputs, where repeating the full
    /// target on every line would be noise.
    pub fn resolve(&self, path: &str) -> Result<Self> {
        if path.starts_with("//") || path.starts_with("smb://") || path.starts_with("\\\\") {
            return Target::parse(path);
        }
        let joined = if self.path.is_empty() {
            trim_path(path)
        } else {
            format!("{}/{}", self.path, trim_path(path))
        };
        Ok(self.with_path(&joined))
    }

    /// Display form, `//host/share/path`.
    pub fn display(&self) -> String {
        let port = if self.port == 445 {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        if self.path.is_empty() {
            format!("//{}{}/{}", self.host, port, self.share)
        } else {
            format!("//{}{}/{}/{}", self.host, port, self.share, self.path)
        }
    }
}

fn trim_path(path: &str) -> String {
    path.trim_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_double_slash_form() {
        let target = Target::parse("//raspi/PiHDD/xiaomi/788b").unwrap();
        assert_eq!(target.host, "raspi");
        assert_eq!(target.port, 445);
        assert_eq!(target.share, "PiHDD");
        assert_eq!(target.path, "xiaomi/788b");
    }

    #[test]
    fn parses_the_smb_scheme_and_a_port() {
        let target = Target::parse("smb://10.0.0.1:4450/share").unwrap();
        assert_eq!(target.host, "10.0.0.1");
        assert_eq!(target.port, 4450);
        assert_eq!(target.share, "share");
        assert_eq!(target.path, "");
    }

    #[test]
    fn parses_the_windows_form() {
        let target = Target::parse(r"\\host\share\dir\file.txt").unwrap();
        assert_eq!(target.share, "share");
        assert_eq!(target.path, "dir/file.txt");
    }

    #[test]
    fn rejects_a_target_without_a_share() {
        assert!(Target::parse("//host").is_err());
        assert!(Target::parse("relative/path").is_err());
    }

    #[test]
    fn resolves_relative_and_absolute_paths() {
        let base = Target::parse("//host/share/base").unwrap();
        assert_eq!(base.resolve("child").unwrap().path, "base/child");
        assert_eq!(
            base.resolve("//other/share2/x").unwrap().display(),
            "//other/share2/x"
        );
    }

    #[test]
    fn round_trips_through_display() {
        for input in ["//host/share", "//host/share/a/b", "//host:4450/share/a"] {
            let target = Target::parse(input).unwrap();
            assert_eq!(target.display(), input);
        }
    }
}
