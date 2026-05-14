use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub tunnel_cert_dir: Option<PathBuf>,
    pub clients: Vec<ClientEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    pub name: String,
    #[serde(deserialize_with = "deserialize_token_hex")]
    pub token: [u8; 32],
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.clients.is_empty() {
            return Err(ConfigError::NoClients);
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
}
