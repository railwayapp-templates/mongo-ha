//! HAProxy configuration generator for MongoDB HA.
//!
//! Architecture (v1 — write frontend only, no read port):
//!   - Port 27017 (writes): HTTP health check on each node's /role endpoint.
//!     Only the node that returns 200 (the current replica set PRIMARY) is
//!     marked UP.
//!   - Port 8404: stats page for observability.
//!
//! The health check hits the Rust health server running on each
//! mongo-wrapper container (HEALTH_CHECK_PORT, default 8080), not mongod
//! directly. This eliminates the need for raw tcp-check sequences in the
//! MongoDB wire protocol.
//!
//! Clients connect to this edge with `directConnection=true` (the template's
//! connection strings carry it): the edge fronts one server at a time, and a
//! driver that instead discovered the replica set topology through it would
//! start dialing the members' private hostnames itself — reachable inside the
//! Railway project, unreachable through a public TCP proxy.
//!
//! There is no read frontend/backend in v1: this image is scoped to failover
//! for the write path, matching Railway's single-click MongoDB HA template.

use crate::config::Config;
use crate::nodes::MongoNode;

fn server_entries(nodes: &[MongoNode], health_port: u16, config: &Config) -> String {
    nodes
        .iter()
        .map(|n| {
            format!(
                "    server {} {}:{} check port {} resolvers railway inter {} fastinter {} downinter {}",
                n.name, n.host, n.mongo_port, health_port,
                config.check_interval, config.check_fastinter, config.check_downinter
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn generate_config(config: &Config, nodes: &[MongoNode]) -> String {
    let servers = server_entries(nodes, config.health_port, config);

    format!(
        r#"global
    maxconn {max_conn}
    log stdout format raw local0

defaults
    log global
    mode tcp
    option tcpka
    option clitcpka
    option srvtcpka
    option redispatch
    retries 3
    timeout connect {timeout_connect}
    timeout client {timeout_client}
    timeout server {timeout_server}
    timeout check {timeout_check}

resolvers railway
    parse-resolv-conf
    resolve_retries 3
    timeout resolve 1s
    timeout retry   1s
    hold other      10s
    hold refused    10s
    hold nx         10s
    hold timeout    10s
    hold valid      10s
    hold obsolete   10s

# Stats page for monitoring
listen stats
    bind :::8404 v4v6
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    # This proxy's own traffic is not worth logging: the in-container
    # monitoring loop scrapes /stats every few seconds and each scrape opens
    # two connections. Carried over from redis-ha, where inheriting `log
    # global` here made self-traffic ~99% of the service's entire log volume,
    # burying the lines an operator actually needs (backend UP/DOWN, DNS
    # re-resolution, client connects).
    no log

# Write traffic — routed exclusively to the current replica set PRIMARY.
# The /role health check returns 200 only on the primary node.
frontend mongo_writes
    bind :::{mongo_port} v4v6
    default_backend mongo_primary_backend

backend mongo_primary_backend
    option httpchk
    http-check send meth GET uri /role
    http-check expect status 200
    # fall 2 + fastinter 500ms: the first failed /role check switches the
    # probe to the fast interval, so a real step-down is confirmed and the
    # server pulled ~500ms after the first failure — but ONE slow or dropped
    # check can no longer RST every client connection on a healthy primary.
    # /role runs two admin commands (2s timeout each) against `timeout check
    # 3s`, so a single blip under load is expected, and with no secondary
    # passing /role a false mark-down is a self-inflicted write outage until
    # `rise 2` readmits the primary. shutdown-sessions RSTs every open client
    # connection the moment the server is genuinely marked down, forcing
    # clients to reconnect and land on the new primary.
    default-server fall 2 rise 2 on-marked-down shutdown-sessions
{servers}
"#,
        max_conn = config.max_conn,
        timeout_connect = config.timeout_connect,
        timeout_client = config.timeout_client,
        timeout_server = config.timeout_server,
        timeout_check = config.timeout_check,
        mongo_port = config.mongo_port,
        servers = servers,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for_tests() -> Config {
        Config {
            mongo_nodes: "mongo-1.railway.internal:27017,mongo-2.railway.internal:27017"
                .to_string(),
            health_port: 8080,
            mongo_port: 27017,
            max_conn: "1000".to_string(),
            timeout_connect: "5s".to_string(),
            timeout_client: "30m".to_string(),
            timeout_server: "30m".to_string(),
            timeout_check: "3s".to_string(),
            check_interval: "3s".to_string(),
            check_fastinter: "500ms".to_string(),
            check_downinter: "500ms".to_string(),
        }
    }

    fn section<'a>(conf: &'a str, header: &str) -> &'a str {
        // Anchor to line start: a bare `find("backend x")` would match the
        // substring inside the frontend's `default_backend x` line.
        let needle = format!("\n{header}");
        let start = conf.find(&needle).expect("section header not found") + 1;
        let rest = &conf[start..];
        match rest.find("\n\n") {
            Some(end) => &rest[..end],
            None => rest,
        }
    }

    /// The stats listener must not log: the in-container monitoring loop
    /// scrapes it every few seconds, and inheriting `log global` made that
    /// self-traffic the bulk of this service's log volume in redis-ha.
    #[test]
    fn stats_listener_does_not_log_its_own_traffic() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);

        assert!(section(&conf, "listen stats").contains("no log"));
    }

    /// ...and silencing it must not silence the proxy that carries real
    /// traffic: it still inherits `log global` from defaults.
    #[test]
    fn write_frontend_still_logs() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);

        assert!(conf.contains("defaults\n    log global"));
        assert!(!section(&conf, "frontend mongo_writes").contains("no log"));
    }

    /// v1 has no read port — the read frontend/backend must not exist at all.
    #[test]
    fn there_is_no_read_frontend_or_backend() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);

        assert!(!conf.contains("frontend mongo_reads"));
        assert!(!conf.contains("mongo_secondary_backend"));
    }

    /// The write frontend binds the configured MONGO_PORT (default 27017),
    /// and routes to the single primary backend via the /role health check.
    #[test]
    fn write_frontend_binds_mongo_port_and_checks_role() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);

        let frontend = section(&conf, "frontend mongo_writes");
        assert!(frontend.contains("bind :::27017 v4v6"));
        assert!(frontend.contains("default_backend mongo_primary_backend"));

        let backend = section(&conf, "backend mongo_primary_backend");
        assert!(backend.contains("http-check send meth GET uri /role"));
        assert!(backend.contains("http-check expect status 200"));
        // fall 2, not 1: one slow /role check on a healthy primary must not
        // RST every client connection (fastinter re-probes 500ms later, so a
        // real step-down is still confirmed almost immediately).
        assert!(backend.contains("default-server fall 2 rise 2 on-marked-down shutdown-sessions"));
    }

    /// The resolvers block must be present with the same tunables redis-ha
    /// shipped — Railway's private network DNS needs re-resolution on
    /// redeploy, and this is what makes HAProxy pick up an IP change.
    #[test]
    fn resolvers_block_is_present() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);

        assert!(conf.contains("resolvers railway"));
        assert!(conf.contains("parse-resolv-conf"));
    }

    /// Every declared node must appear as a `server` line in the primary
    /// backend, health-checked against the wrapper's health port.
    #[test]
    fn every_node_gets_a_server_line() {
        let config = config_for_tests();
        let nodes = crate::nodes::parse_nodes(&config.mongo_nodes).unwrap();
        let conf = generate_config(&config, &nodes);
        let backend = section(&conf, "backend mongo_primary_backend");

        assert!(backend.contains("server mongo-1 mongo-1.railway.internal:27017 check port 8080"));
        assert!(backend.contains("server mongo-2 mongo-2.railway.internal:27017 check port 8080"));
    }
}
