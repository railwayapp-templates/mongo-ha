use anyhow::{anyhow, Result};

pub struct MongoNode {
    pub name: String,
    pub host: String,
    pub mongo_port: u16,
}

/// Parse the MONGO_NODES env var.
///
/// Format: "hostname:port,hostname:port,..."
/// Example: "mongo-1.railway.internal:27017,mongo-2.railway.internal:27017"
pub fn parse_nodes(mongo_nodes: &str) -> Result<Vec<MongoNode>> {
    mongo_nodes
        .split(',')
        .map(|entry| {
            let entry = entry.trim();
            let parts: Vec<&str> = entry.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "invalid node format: '{}'. Expected hostname:port",
                    entry
                ));
            }
            let host = parts[0].to_string();
            let mongo_port = parts[1]
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port in '{}': {}", entry, parts[1]))?;
            let name = host.split('.').next().unwrap_or(&host).to_string();

            Ok(MongoNode {
                name,
                host,
                mongo_port,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_and_ports_in_declared_order() {
        let nodes =
            parse_nodes("mongo-1.railway.internal:27017, mongo-2.railway.internal:27018").unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "mongo-1");
        assert_eq!(nodes[0].host, "mongo-1.railway.internal");
        assert_eq!(nodes[0].mongo_port, 27017);
        assert_eq!(nodes[1].name, "mongo-2");
        assert_eq!(nodes[1].mongo_port, 27018);
    }

    #[test]
    fn rejects_entries_without_a_port() {
        assert!(parse_nodes("mongo-1.railway.internal").is_err());
        assert!(parse_nodes("mongo-1.railway.internal:notaport").is_err());
    }
}
