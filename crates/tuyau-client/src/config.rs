use serde::{Deserialize, Deserializer};

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    #[serde(deserialize_with = "deserialize_hex_32")]
    pub server_cert_fingerprint_sha256: [u8; 32],
    #[serde(deserialize_with = "deserialize_hex_32")]
    pub token: [u8; 32],
    pub client_name: String,
}

impl ClientConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }
}

fn deserialize_hex_32<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(de)?;
    let bytes = hex::decode(&s).map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?;

    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        D::Error::custom(format!(
            "expected 32 bytes (64 hex chars), got {} bytes",
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
            server_addr = "tunnel.example.com:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "service-a"
        "#;
        let cfg = ClientConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.server_addr, "tunnel.example.com:4433");
        assert_eq!(cfg.server_cert_fingerprint_sha256[31], 0xaa);
        assert_eq!(cfg.token[31], 0xbb);
        assert_eq!(cfg.client_name, "service-a");
    }

    #[test]
    fn rejects_short_fingerprint() {
        let toml = r#"
            server_addr = "127.0.0.1:4433"
            server_cert_fingerprint_sha256 = "deadbeef"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "a"
        "#;
        assert!(ClientConfig::from_toml_str(toml).is_err());
    }

    #[test]
    fn rejects_non_hex_token() {
        let toml = r#"
            server_addr = "127.0.0.1:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "ZZ00000000000000000000000000000000000000000000000000000000000000"
            client_name = "a"
        "#;
        assert!(ClientConfig::from_toml_str(toml).is_err());
    }
}
