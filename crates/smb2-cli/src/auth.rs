//! Working out which username and password to connect with.

use std::io::IsTerminal;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Credentials for one SMB connection, and whether it must encrypt. `Debug`
/// shows the password as `***`.
#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// `--require-encryption`: refuse a connection that would run in the clear.
    pub require_encryption: bool,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &format_args!("***"))
            .field("require_encryption", &self.require_encryption)
            .finish()
    }
}

impl Credentials {
    /// Connect to `addr` as these credentials say: five-second timeout,
    /// compression on, and encryption required when asked for.
    pub async fn connect(&self, addr: &str) -> smb2::Result<smb2::SmbClient> {
        smb2::SmbClient::connect(smb2::ClientConfig {
            addr: addr.to_string(),
            timeout: std::time::Duration::from_secs(5),
            username: self.username.clone(),
            password: self.password.clone(),
            require_encryption: self.require_encryption,
            ..Default::default()
        })
        .await
    }
}

/// The credential-related flags, shared by every command. `Debug` shows the
/// password as `***`.
#[derive(Clone, clap::Args)]
pub struct AuthArgs {
    /// Username to log in with.
    #[arg(short = 'u', long, env = "SMB2_USER", global = true)]
    pub user: Option<String>,

    /// Password. Prefer `--password-command` so it stays out of your shell history.
    #[arg(long, env = "SMB2_PASS", global = true, hide_env_values = true)]
    pub password: Option<String>,

    /// Shell command that prints the password on stdout, for example
    /// `--password-command 'secret RASPI_SMB_PASSWORD'`.
    #[arg(long, env = "SMB2_PASS_COMMAND", global = true)]
    pub password_command: Option<String>,

    /// Connect as guest (no username or password).
    #[arg(long, global = true, conflicts_with_all = ["user", "password", "password_command"])]
    pub guest: bool,

    /// Encrypt everything, or refuse to connect: the session encrypts even
    /// when the server only allows it, and a server that agrees on no cipher
    /// (or answers with a guest session) fails the connection rather than
    /// running in the clear.
    #[arg(long, global = true)]
    pub require_encryption: bool,
}

impl std::fmt::Debug for AuthArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthArgs")
            .field("user", &self.user)
            .field(
                "password",
                &self.password.as_ref().map(|_| format_args!("***")),
            )
            .field("password_command", &self.password_command)
            .field("guest", &self.guest)
            .field("require_encryption", &self.require_encryption)
            .finish()
    }
}

impl AuthArgs {
    /// Resolves credentials, prompting on a terminal when nothing else supplied
    /// a password.
    pub fn resolve(&self) -> Result<Credentials> {
        let (username, password) = self.login()?;
        Ok(Credentials {
            username,
            password,
            require_encryption: self.require_encryption,
        })
    }

    /// The username and password, from the first source that has them.
    fn login(&self) -> Result<(String, String)> {
        if self.guest {
            return Ok((String::new(), String::new()));
        }

        let username = self
            .user
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no username: pass --user or set SMB2_USER"))?;

        if let Some(command) = &self.password_command {
            let output = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .with_context(|| format!("running --password-command {command:?}"))?;
            if !output.status.success() {
                bail!(
                    "--password-command {command:?} failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            let password = String::from_utf8(output.stdout)
                .context("--password-command printed invalid UTF-8")?
                .trim_end_matches(['\n', '\r'])
                .to_string();
            return Ok((username, password));
        }

        if let Some(password) = &self.password {
            return Ok((username, password.clone()));
        }

        if std::io::stdin().is_terminal() {
            let password = rpassword::prompt_password(format!("Password for {username}: "))
                .context("reading the password")?;
            return Ok((username, password));
        }

        bail!("no password: pass --password-command, set SMB2_PASS, or run on a terminal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_password() {
        let creds = Credentials {
            username: "david".to_string(),
            password: "hunter2-secret".to_string(),
            require_encryption: false,
        };
        let args = AuthArgs {
            user: Some("david".to_string()),
            password: Some("hunter2-secret".to_string()),
            password_command: None,
            guest: false,
            require_encryption: false,
        };
        for printed in [format!("{creds:?}"), format!("{args:?}")] {
            assert!(!printed.contains("hunter2"), "{printed}");
            assert!(printed.contains("***"), "{printed}");
            assert!(printed.contains("david"), "{printed}");
        }
    }
}
