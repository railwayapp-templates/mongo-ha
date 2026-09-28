//! SERVER-121912: MongoDB's TCMalloc per-CPU cache is incompatible with
//! Linux 6.19.0 through 7.0.13. Let glibc own rseq on those kernels so
//! TCMalloc uses its fallback allocator path. Match the bounds in MongoDB
//! 8.0.32's startup_check_rseq.cpp; leave other kernels unchanged.
//!
//! Apply before exec, to the entrypoint's environment: this also covers its
//! initialization server, recovery boots and supervised mongod restarts.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::OnceLock;
use tokio::process::Command;
use tracing::{info, warn};

const RSEQ_KEY: &[u8] = b"glibc.pthread.rseq=";
const RSEQ_FALLBACK: &[u8] = b"glibc.pthread.rseq=1";
static CHILD_TUNABLES: OnceLock<Option<OsString>> = OnceLock::new();

/// Configure only the child; never mutate the multithreaded wrapper's environment.
pub fn configure_mongod(command: &mut Command) {
    let tunables = CHILD_TUNABLES.get_or_init(|| {
        // procfs reports the running host kernel, not the image's distro version.
        let release = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            Ok(release) => release,
            Err(error) => {
                warn!(%error, "could not read kernel release; preserving mongod allocator environment");
                return None;
            }
        };
        let affected = match affected_kernel(&release) {
            Some(affected) => affected,
            None => {
                warn!(kernel = release.trim(), "unrecognized kernel release; preserving mongod allocator environment");
                return None;
            }
        };
        if !affected {
            return None;
        }
        let inherited = std::env::var_os("GLIBC_TUNABLES");
        // Do not log the full environment or unrelated caller-supplied tunables.
        info!(
            kernel = release.trim(),
            workaround = "glibc.pthread.rseq=1",
            "using MongoDB allocator fallback for SERVER-121912; per-CPU cache optimization is disabled"
        );
        Some(with_rseq_fallback(inherited.as_deref()))
    });
    if let Some(tunables) = tunables {
        command.env("GLIBC_TUNABLES", tunables);
    }
}

fn affected_kernel(release: &str) -> Option<bool> {
    let mut parts = release.trim().splitn(3, '.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let tail = parts.next()?;
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    let patch: u32 = tail[..digits].parse().ok()?;
    if !tail[digits..].is_empty() && !matches!(tail.as_bytes()[digits], b'-' | b'+' | b'.') {
        return None;
    }
    let version = (major, minor, patch);
    Some(((6, 19, 0)..(7, 0, 14)).contains(&version))
}

/// Replace every rseq entry (including duplicates), keeping all other tunables.
/// Environment values need not be UTF-8, so preserve their bytes.
fn with_rseq_fallback(inherited: Option<&OsStr>) -> OsString {
    let mut entries: Vec<&[u8]> = inherited
        .map(OsStrExt::as_bytes)
        .unwrap_or_default()
        .split(|byte| *byte == b':')
        .filter(|entry| !entry.is_empty() && !entry.starts_with(RSEQ_KEY))
        .collect();
    entries.push(RSEQ_FALLBACK);
    OsString::from_vec(entries.join(&b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_range_matches_mongodb_including_distro_suffixes() {
        for release in [
            "6.19.0",
            "6.19.10+deb13-cloud-amd64",
            "6.20.2-custom",
            "6.100.0",
            "7.0.0",
            "7.0.13-generic",
        ] {
            assert_eq!(affected_kernel(release), Some(true), "{release}");
        }
        for release in [
            "5.15.0",
            "6.18.15+deb13-cloud-amd64",
            "7.0.14",
            "7.0.14-orbstack-00380",
            "7.1.0",
            "8.0.0",
        ] {
            assert_eq!(affected_kernel(release), Some(false), "{release}");
        }
        assert_eq!(affected_kernel("6.19.10+deb13-cloud-amd64\n"), Some(true));
    }

    #[test]
    fn unknown_versions_do_not_request_an_override() {
        for release in [
            "",
            "6",
            "6.19",
            "6.19.x",
            "Linux 6.19.0",
            "6.19.0garbage",
            "999999999999999999999.0.0",
        ] {
            assert_eq!(affected_kernel(release), None, "{release}");
        }
    }

    #[test]
    fn replaces_only_rseq_and_removes_conflicting_duplicates() {
        let original = OsStr::new("glibc.malloc.arena_max=2:glibc.pthread.rseq=0:glibc.cpu.hwcaps=-SHSTK:glibc.pthread.rseq=0");
        assert_eq!(
            with_rseq_fallback(Some(original)),
            OsStr::new("glibc.malloc.arena_max=2:glibc.cpu.hwcaps=-SHSTK:glibc.pthread.rseq=1")
        );
    }

    #[test]
    fn handles_absent_empty_and_already_enabled_tunables() {
        for original in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("glibc.pthread.rseq=1")),
        ] {
            assert_eq!(
                with_rseq_fallback(original),
                OsStr::new("glibc.pthread.rseq=1")
            );
        }
        assert_eq!(
            with_rseq_fallback(Some(OsStr::new("glibc.malloc.arena_max=2"))),
            OsStr::new("glibc.malloc.arena_max=2:glibc.pthread.rseq=1")
        );
    }

    #[test]
    fn preserves_non_utf8_unrelated_values() {
        let original = OsStr::from_bytes(b"other=\xff:glibc.pthread.rseq=0");
        assert_eq!(
            with_rseq_fallback(Some(original)).as_bytes(),
            b"other=\xff:glibc.pthread.rseq=1"
        );
    }
}
