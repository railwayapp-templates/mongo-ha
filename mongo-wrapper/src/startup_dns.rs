//! Gate an existing replica-set dataset's startup on its own DNS identity.
//! This never rewrites the stored replica-set config or starts a new set.
use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::time::Duration;
use tracing::info;

/// Binding an ephemeral port proves an address belongs to this container,
/// rather than a previous deployment still present in DNS. The listener is
/// dropped immediately; no application port is occupied.
fn is_local_address(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && TcpListener::bind(SocketAddr::new(ip, 0)).is_ok()
}

async fn resolves_locally(host: &str) -> bool {
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((host, 0))).await {
        Ok(Ok(mut addresses)) => addresses.any(|a| is_local_address(a.ip())),
        _ => false,
    }
}

pub async fn wait_for_local_address(host: &str) -> Result<()> {
    info!(%host, "waiting for this node's DNS to resolve to a local address before opening the replica-set dataset");
    let ready = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if resolves_locally(host).await {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    if ready.is_err() {
        bail!("own replica-set hostname {host} did not resolve to a local address within 120s; refusing to open the dataset");
    }
    info!(%host, "replica-set hostname resolves to this container");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_local_identity_but_not_wildcard_multicast_or_remote_addresses() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        for ip in ["0.0.0.0", "::", "224.0.0.1", "ff02::1", "192.0.2.1"] {
            assert!(!is_local_address(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn requires_resolved_address_to_belong_to_this_container() {
        assert!(resolves_locally("localhost").await);
        assert!(!resolves_locally("192.0.2.1").await);
        assert!(!resolves_locally("mongo-ha-self-does-not-exist.invalid").await);
    }
}
