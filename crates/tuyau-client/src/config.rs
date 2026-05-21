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
    /// Local forwarding rules: which public hostname maps to which local
    /// `host:port`. Purely client-side — never sent to the server.
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngressRule {
    pub host: String,
    pub local_addr: String,
}

impl ClientConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: ClientConfig = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Surface obvious config errors (malformed `local_addr` shapes) at load
    /// time rather than at the first incoming public request.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (i, rule) in self.ingress.iter().enumerate() {
            validate_local_addr(&rule.local_addr)
                .map_err(|reason| ConfigError::InvalidIngress { index: i, reason })?;
        }
        Ok(())
    }
}

/// Lightweight `host:port` shape check. Accepts hostnames (so Docker DNS
/// names like `app:8080` work), so we don't enforce a strict `SocketAddr`
/// parse — only that there is a port and it's numeric.
pub(crate) fn validate_local_addr(s: &str) -> Result<(), String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("local_addr '{s}': missing ':port'"))?;
    // IPv6 literals must be bracketed (e.g. `[::1]:8080`); a bare `::1:8080`
    // is ambiguous. If host contains a `:` without brackets, reject.
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(format!(
            "local_addr '{s}': IPv6 hosts must be bracketed (e.g. '[::1]:8080')"
        ));
    }
    if host.is_empty() {
        return Err(format!("local_addr '{s}': empty host before ':'"));
    }
    port.parse::<u16>()
        .map_err(|_| format!("local_addr '{s}': '{port}' is not a valid port"))?;
    Ok(())
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
        assert!(cfg.ingress.is_empty());
    }

    #[test]
    fn parses_ingress_rules() {
        let toml = r#"
            server_addr = "tunnel.example.com:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "service-a"
            [[ingress]]
            host = "alpha.example.com"
            local_addr = "127.0.0.1:8080"
            [[ingress]]
            host = "beta.example.com"
            local_addr = "127.0.0.1:9000"
        "#;
        let cfg = ClientConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.ingress.len(), 2);
        assert_eq!(cfg.ingress[0].host, "alpha.example.com");
        assert_eq!(cfg.ingress[0].local_addr, "127.0.0.1:8080");
        assert_eq!(cfg.ingress[1].host, "beta.example.com");
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
    fn rejects_ingress_missing_port() {
        let toml = r#"
            server_addr = "tunnel.example.com:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "a"
            [[ingress]]
            host = "alpha.example.com"
            local_addr = "127.0.0.1"
        "#;
        let err = ClientConfig::from_toml_str(toml).unwrap_err();
        match err {
            ConfigError::InvalidIngress { index, reason } => {
                assert_eq!(index, 0);
                assert!(reason.contains("missing"), "got reason: {reason}");
            }
            other => panic!("expected InvalidIngress, got {other:?}"),
        }
    }

    #[test]
    fn rejects_ingress_non_numeric_port() {
        let toml = r#"
            server_addr = "tunnel.example.com:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "a"
            [[ingress]]
            host = "alpha.example.com"
            local_addr = "127.0.0.1:abc"
        "#;
        let err = ClientConfig::from_toml_str(toml).unwrap_err();
        match err {
            ConfigError::InvalidIngress { reason, .. } => {
                assert!(reason.contains("port"), "got reason: {reason}");
            }
            other => panic!("expected InvalidIngress, got {other:?}"),
        }
    }

    #[test]
    fn accepts_ingress_with_hostname_port() {
        // Docker DNS names like `app:8080` must pass — local_addr is not a
        // strict SocketAddr.
        let toml = r#"
            server_addr = "tunnel.example.com:4433"
            server_cert_fingerprint_sha256 = "00000000000000000000000000000000000000000000000000000000000000aa"
            token = "00000000000000000000000000000000000000000000000000000000000000bb"
            client_name = "a"
            [[ingress]]
            host = "alpha.example.com"
            local_addr = "app:8080"
            [[ingress]]
            host = "v6.example.com"
            local_addr = "[::1]:8443"
        "#;
        let cfg = ClientConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.ingress[0].local_addr, "app:8080");
        assert_eq!(cfg.ingress[1].local_addr, "[::1]:8443");
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
