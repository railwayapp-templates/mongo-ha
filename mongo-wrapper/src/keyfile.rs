//! Internal-authentication keyfile, derived — never stored — from RS_KEY.
//!
//! A replica set with authentication enabled needs every member to present
//! the same keyfile (`--keyFile`), and mongod is picky about its shape: 6 to
//! 1024 characters from the base64 alphabet, owned by the mongod user, not
//! group/world readable. The template hands every node the same shared secret
//! by reference (RS_KEY = the root password, which is what actually resolves
//! on a standalone → HA conversion — see the template seed); hashing it to
//! base64 here means ANY secret value is a valid keyfile, and the keyfile
//! never equals the password itself.
//!
//! Written outside the data dir: it is a pure function of the environment,
//! regenerated on every boot, never state to back up or preserve.

use anyhow::{Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{info, warn};

/// The user the upstream image's docker-entrypoint.sh drops privileges to
/// before exec'ing mongod. mongod must be able to read the keyfile as it.
const MONGOD_USER: &str = "mongodb";

/// The keyfile content for a shared secret: base64 of its SHA-256, 44 chars.
pub fn derive_keyfile_content(shared_secret: &str) -> String {
    let digest = Sha256::digest(shared_secret.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Write the keyfile for `shared_secret` at `path`, readable only by the
/// mongod user. Errors are fatal: HA mode cannot start without it.
pub fn write_keyfile(path: &str, shared_secret: &str) -> Result<()> {
    let path = Path::new(path);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)
            .with_context(|| format!("could not create keyfile directory {}", dir.display()))?;
    }
    fs::write(path, derive_keyfile_content(shared_secret))
        .with_context(|| format!("could not write keyfile {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))
        .with_context(|| format!("could not chmod keyfile {}", path.display()))?;

    // Ownership: the entrypoint re-execs as `mongodb` when started as root
    // (Railway's case), so the 0400 file must belong to that user. When the
    // user does not exist (a non-standard base image) or we are not root,
    // leave ownership alone — mongod then reads it as whoever runs it.
    match nix::unistd::User::from_name(MONGOD_USER) {
        Ok(Some(user)) => {
            if let Err(e) = nix::unistd::chown(path, Some(user.uid), Some(user.gid)) {
                warn!(error = %e, user = MONGOD_USER, "could not chown the keyfile; mongod may refuse it");
            }
        }
        Ok(None) => warn!(
            user = MONGOD_USER,
            "mongod user not found; keyfile left owned by the wrapper"
        ),
        Err(e) => {
            warn!(error = %e, "could not look up the mongod user; keyfile left owned by the wrapper")
        }
    }

    info!(path = %path.display(), "keyfile written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_base64_and_deterministic() {
        let a = derive_keyfile_content("secret");
        let b = derive_keyfile_content("secret");
        assert_eq!(a, b);
        assert_eq!(a.len(), 44);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
        assert_ne!(a, derive_keyfile_content("other"));
    }

    /// Any password shape — including characters outside mongod's keyfile
    /// alphabet — yields a valid keyfile, which is the whole point of hashing.
    #[test]
    fn awkward_secrets_still_yield_valid_keyfiles() {
        let content = derive_keyfile_content("p@ss word!\n$%^");
        assert!(content.len() >= 6 && content.len() <= 1024);
        assert!(!content.contains(char::is_whitespace));
    }

    #[test]
    fn writes_a_read_only_file() {
        let dir = std::env::temp_dir().join(format!("mongo-keyfile-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("keyfile");
        write_keyfile(path.to_str().unwrap(), "secret").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            derive_keyfile_content("secret")
        );
        fs::remove_dir_all(&dir).ok();
    }
}
