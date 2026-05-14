use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

pub use tuyau_protocol::TlsMode;

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    #[serde(default)]
    pub public_listen_addr: Option<SocketAddr>,
    pub tunnel_cert_dir: Option<PathBuf>,
    pub clients: Vec<ClientEntry>,
    #[serde(default)]
    pub hostnames: Vec<HostnameEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    pub name: String,
    #[serde(deserialize_with = "deserialize_token_hex")]
    pub token: [u8; 32],
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostnameEntry {
    pub host: String,
    pub client: String,
    #[serde(default)]
    pub tls_mode: TlsMode,
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.clients.is_empty() {
            return Err(ConfigError::NoClients);
        }

        let mut seen_hosts: HashSet<&str> = HashSet::new();
        for h in &self.hostnames {
            if !seen_hosts.insert(h.host.as_str()) {
                return Err(ConfigError::DuplicateHost(h.host.clone()));
            }
        }

        let known_clients: HashSet<&str> = self.clients.iter().map(|c| c.name.as_str()).collect();
        for h in &self.hostnames {
            if !known_clients.contains(h.client.as_str()) {
                return Err(ConfigError::UnknownClient {
                    host: h.host.clone(),
                    client: h.client.clone(),
                });
            }
        }

        Ok(())
    }
}

fn deserialize_token_hex<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(de)?;
    let bytes =
        hex::decode(&s).map_err(|e| D::Error::custom(format!("token: invalid hex: {e}")))?;

    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        D::Error::custom(format!(
            "token: expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            tunnel_cert_dir = "/var/lib/tuyau"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[clients]]
            name = "b"
            token = "0000000000000000000000000000000000000000000000000000000000000002"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.clients.len(), 2);
        assert_eq!(cfg.clients[0].token[31], 1);
        assert_eq!(cfg.clients[1].token[31], 2);
        assert!(cfg.hostnames.is_empty());
    }

    #[test]
    fn parses_hostnames_section() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "alpha.example.com"
            client = "a"
            [[hostnames]]
            host = "beta.example.com"
            client = "a"
            tls_mode = "passthrough"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.hostnames.len(), 2);
        assert_eq!(cfg.hostnames[0].host, "alpha.example.com");
        assert_eq!(cfg.hostnames[0].tls_mode, TlsMode::Terminated);
        assert_eq!(cfg.hostnames[1].tls_mode, TlsMode::Passthrough);
    }

    #[test]
    fn rejects_empty_clients() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            clients = []
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::NoClients)));
    }

    #[test]
    fn rejects_short_token() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "deadbeef"
        "#;
        assert!(ServerConfig::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_non_hex_token() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "xx00000000000000000000000000000000000000000000000000000000000000"
        "#;
        assert!(ServerConfig::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_duplicate_host() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "alpha.example.com"
            client = "a"
            [[hostnames]]
            host = "alpha.example.com"
            client = "a"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        match cfg.validate() {
            Err(ConfigError::DuplicateHost(h)) => assert_eq!(h, "alpha.example.com"),
            other => panic!("expected DuplicateHost, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_client_reference() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "alpha.example.com"
            client = "ghost"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        match cfg.validate() {
            Err(ConfigError::UnknownClient { host, client }) => {
                assert_eq!(host, "alpha.example.com");
                assert_eq!(client, "ghost");
            }
            other => panic!("expected UnknownClient, got {other:?}"),
        }
    }

    #[test]
    fn tls_mode_defaults_to_terminated() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "alpha.example.com"
            client = "a"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.hostnames[0].tls_mode, TlsMode::Terminated);
    }
}
