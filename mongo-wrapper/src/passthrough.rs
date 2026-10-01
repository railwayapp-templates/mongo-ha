//! The mongod flags handed to this process, merged with the wrapper's own.
//!
//! Two callers put flags here: the image's CMD (extra mongod flags, see the
//! Dockerfile) and a Railway start command written for the OFFICIAL image —
//! `docker-entrypoint.sh mongod --ipv6 --bind_ip ::,0.0.0.0 --setParameter
//! diagnosticDataCollectionEnabled=false` is what the standalone template
//! stamps — which the entrypoint shim routes into the wrapper as
//! `mongo-wrapper --ipv6 --bind_ip ... `. mongod refuses a repeated option
//! ("Multiple occurrences of option --ipv6") and `--bind_ip` together with
//! `--bind_ip_all`, so the wrapper's defaults yield to whatever the args
//! already say; the wrapper then reads the values it needs (the port, the
//! dbpath) back out of the args so it supervises the mongod that actually
//! runs.

/// The option name of one argv token: `--port` for `--port`, `--port=27018`
/// and (mongod accepts a single dash too) `-port`.
fn option_name(token: &str) -> Option<&str> {
    let body = token
        .strip_prefix("--")
        .or_else(|| token.strip_prefix('-'))?;
    if body.is_empty() || body.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some(body.split('=').next().unwrap_or(body))
}

/// Whether the passthrough args set `name` (`--name`, `--name=v`, `-name`).
pub fn args_set(args: &[String], name: &str) -> bool {
    args.iter().any(|t| option_name(t) == Some(name))
}

/// The value the passthrough args give `name`, as `--name v` or `--name=v`.
pub fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(t) = it.next() {
        if option_name(t) != Some(name) {
            continue;
        }
        if let Some((_, v)) = t.split_once('=') {
            return Some(v);
        }
        return it.next().map(String::as_str);
    }
    None
}

/// The wrapper's own flags with every option the passthrough args already
/// set removed — a flag and, for the paired form (`--port 27017`), its value.
/// `--bind_ip_all` also yields to a passthrough `--bind_ip`: mongod treats
/// the pair as a conflict, and an explicit bind list is the more specific
/// instruction.
pub fn merge_own_flags(own: &[String], args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(own.len());
    let mut it = own.iter().peekable();
    while let Some(flag) = it.next() {
        let Some(name) = option_name(flag) else {
            out.push(flag.clone());
            continue;
        };
        // The paired value, when the next own token is not itself an option.
        let takes_value = it.peek().is_some_and(|next| option_name(next).is_none());
        let value = if takes_value {
            it.next().cloned()
        } else {
            None
        };
        let overridden = args_set(args, name)
            || (name == "bind_ip_all" && args_set(args, "bind_ip"))
            || (name == "bind_ip" && args_set(args, "bind_ip_all"));
        if overridden {
            continue;
        }
        out.push(flag.clone());
        if let Some(v) = value {
            out.push(v);
        }
    }
    out
}

/// The port mongod will actually listen on when the args name one.
pub fn passthrough_port(args: &[String]) -> Option<u16> {
    arg_value(args, "port").and_then(|v| v.trim().parse().ok())
}

/// The dbpath mongod will actually open when the args name one.
pub fn passthrough_dbpath(args: &[String]) -> Option<String> {
    arg_value(args, "dbpath")
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn own() -> Vec<String> {
        v(&["--bind_ip_all", "--ipv6", "--port", "27017"])
    }

    #[test]
    fn no_passthrough_keeps_every_own_flag() {
        assert_eq!(merge_own_flags(&own(), &[]), own());
        let extra = v(&["--setParameter", "diagnosticDataCollectionEnabled=false"]);
        assert_eq!(merge_own_flags(&own(), &extra), own());
    }

    #[test]
    fn the_standalone_templates_start_command_boots_without_duplicates() {
        // What the shim hands over from `docker-entrypoint.sh mongod --ipv6
        // --bind_ip ::,0.0.0.0 --setParameter diagnosticDataCollectionEnabled=false`.
        let args = v(&[
            "--ipv6",
            "--bind_ip",
            "::,0.0.0.0",
            "--setParameter",
            "diagnosticDataCollectionEnabled=false",
        ]);
        assert_eq!(merge_own_flags(&own(), &args), v(&["--port", "27017"]));
    }

    #[test]
    fn a_passthrough_port_replaces_the_pair_and_is_read_back() {
        let args = v(&["--port=27018"]);
        assert_eq!(
            merge_own_flags(&own(), &args),
            v(&["--bind_ip_all", "--ipv6"])
        );
        assert_eq!(passthrough_port(&args), Some(27018));
        assert_eq!(passthrough_port(&v(&["--port", "27019"])), Some(27019));
        assert_eq!(passthrough_port(&v(&["--port"])), None);
        assert_eq!(passthrough_port(&[]), None);
    }

    #[test]
    fn dbpath_is_read_back_and_the_own_pair_dropped() {
        let own = v(&["--dbpath", "/data/db", "--ipv6"]);
        let args = v(&["--dbpath", "/mnt/mongo"]);
        assert_eq!(merge_own_flags(&own, &args), v(&["--ipv6"]));
        assert_eq!(passthrough_dbpath(&args).as_deref(), Some("/mnt/mongo"));
    }

    #[test]
    fn single_dash_and_equals_forms_count_as_set() {
        assert!(args_set(&v(&["-ipv6"]), "ipv6"));
        assert!(args_set(&v(&["--bind_ip=::"]), "bind_ip"));
        assert!(!args_set(&v(&["--bind_ip_all"]), "bind_ip"));
        // A negative number is a value, never an option.
        assert_eq!(option_name("-1"), None);
    }

    #[test]
    fn replset_and_keyfile_are_never_yielded_by_default_flags() {
        // HA flags are the wrapper's contract, not defaults: they stay unless
        // the args name the very same option (a misconfiguration mongod will
        // then report itself).
        let own = v(&["--replSet", "rs0", "--keyFile", "/run/k"]);
        assert_eq!(merge_own_flags(&own, &v(&["--ipv6"])), own);
    }
}
