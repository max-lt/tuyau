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
    /// Optional ACME configuration. When set, the public listener uses
    /// rustls-acme to fetch real browser-trusted certs via TLS-ALPN-01
    /// instead of the dev-mode self-signed multi-SAN cert. Applies to
    /// `terminated` hostnames only — passthrough never needs a cert.
    #[serde(default)]
    pub acme: Option<AcmeSection>,
    /// Optional path to a PEM certificate chain (leaf first) for the public
    /// listener. When set — and `acme` is not — the listener serves this cert
    /// for all terminated hostnames instead of a self-signed one. Useful for a
    /// cert obtained out-of-band (e.g. Let's Encrypt via DNS-01) when inbound
    /// TLS-ALPN-01 validation isn't possible. Requires `tls_key_file` too.
    #[serde(default)]
    pub tls_cert_file: Option<PathBuf>,
    /// Private key (PEM) matching `tls_cert_file`.
    #[serde(default)]
    pub tls_key_file: Option<PathBuf>,
    /// Static local upstreams: hostnames served by forwarding to a local
    /// address rather than a client tunnel (see [`UpstreamEntry`]). Empty by
    /// default; valid in both static and dynamic mode.
    #[serde(default)]
    pub upstreams: Vec<UpstreamEntry>,
    /// Cap on concurrent public connections being handled. Beyond it, new public
    /// connections are shed (accepted then closed at once) so a flood can't grow
    /// tasks / memory / file descriptors without bound. `None` uses the default
    /// (1024). Only relevant when `public_listen_addr` is set.
    #[serde(default)]
    pub max_public_connections: Option<usize>,
    /// Path to a custom HTML page served as the 502 body when a terminated
    /// hostname has no live backend. `None` uses the built-in default. Lets a
    /// deployment brand it (e.g. add a dashboard link).
    #[serde(default)]
    pub error_502_file: Option<PathBuf>,
}

/// ACME / Let's Encrypt parameters. The default `directory_url` points at LE
/// **staging** (rate-limit-friendly, untrusted certs) — flip `production` to
/// true for real Let's Encrypt certs. `contact` is the email the CA notifies
/// for expiry / policy issues.
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeSection {
    /// `mailto:` URL the CA contacts on issues.
    pub contact: String,
    /// Directory where the ACME account key + cached certs are persisted
    /// across restarts.
    pub cache_dir: PathBuf,
    /// If `true`, use the LE production directory. If `false` (default),
    /// use LE staging — strongly recommended for first deployment so rate
    /// limits don't bite during config iteration.
    #[serde(default)]
    pub production: bool,
}

/// How the server treats multiple concurrent tunnels authenticating as the
/// same client identity (same token).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Balance {
    /// The newest tunnel replaces the previous one for that client's
    /// hostnames; the old connection is closed. Good for reconnects.
    #[default]
    LastWriteWins,
    /// Every concurrent tunnel for the client stays registered and public
    /// connections are spread across them round-robin. Active-active fan-out.
    RoundRobin,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientEntry {
    pub name: String,
    #[serde(deserialize_with = "deserialize_token_hex")]
    pub token: [u8; 32],
    /// Behaviour when several tunnels share this client's token. Defaults to
    /// `last-write-wins`.
    #[serde(default)]
    pub balance: Balance,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostnameEntry {
    pub host: String,
    pub client: String,
    #[serde(default)]
    pub tls_mode: TlsMode,
}

/// A static local upstream: a hostname served by forwarding to a local address
/// instead of a client tunnel. Lets the server front existing local services —
/// e.g. route `db.example.com` to `127.0.0.1:8443`. `passthrough` forwards the
/// raw TLS bytes (the upstream terminates its own TLS, so this box never sees
/// plaintext); `terminated` has the server terminate TLS (it must hold a cert
/// for the host) and forward plaintext. Local upstreams win over tunnel routes
/// for the same host, so a dynamic client can't hijack one.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamEntry {
    pub host: String,
    /// Forward to a local TCP address. Exactly one of `local_addr` /
    /// `local_socket` must be set.
    #[serde(default)]
    pub local_addr: Option<SocketAddr>,
    /// Forward to a local Unix domain socket (e.g. `/run/tuyau/app.sock`).
    /// Exactly one of `local_addr` / `local_socket` must be set.
    #[serde(default)]
    pub local_socket: Option<PathBuf>,
    #[serde(default)]
    pub tls_mode: TlsMode,
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // A server must route *something* — at least one tunnel client or one
        // static local upstream (a front-only deployment has no clients).
        if self.clients.is_empty() && self.upstreams.is_empty() {
            return Err(ConfigError::NoClients);
        }

        // Client names must be unique: hostnames are bound to a client by name,
        // so two entries sharing a name would split one logical identity across
        // tokens (and pick a balance per matched entry) — a silent foot-gun.
        let mut seen_clients: HashSet<&str> = HashSet::new();
        for c in &self.clients {
            if !seen_clients.insert(c.name.as_str()) {
                return Err(ConfigError::DuplicateClient(c.name.clone()));
            }
        }

        let mut seen_hosts: HashSet<&str> = HashSet::new();
        for h in &self.hostnames {
            if !seen_hosts.insert(h.host.as_str()) {
                return Err(ConfigError::DuplicateHost(h.host.clone()));
            }
        }
        // Local upstreams share the hostname namespace: a host can't be both a
        // tunnel route and a local upstream (nor two upstreams).
        for u in &self.upstreams {
            if !seen_hosts.insert(u.host.as_str()) {
                return Err(ConfigError::DuplicateHost(u.host.clone()));
            }
        }
        self.validate_upstream_targets()?;

        let known_clients: HashSet<&str> = self.clients.iter().map(|c| c.name.as_str()).collect();
        for h in &self.hostnames {
            if !known_clients.contains(h.client.as_str()) {
                return Err(ConfigError::UnknownClient {
                    host: h.host.clone(),
                    client: h.client.clone(),
                });
            }
        }

        self.validate_acme()
    }

    /// Validation for dynamic mode (`dynamic` feature): the routing backend
    /// owns clients + hostnames, so only the non-routing config (ACME contact)
    /// is checked. In particular, an empty `clients` list is allowed.
    #[cfg(feature = "dynamic")]
    pub fn validate_dynamic(&self) -> Result<(), ConfigError> {
        // Hostnames are backend-owned in dynamic mode, but upstreams are still
        // static config — keep them unique among themselves.
        let mut seen: HashSet<&str> = HashSet::new();
        for u in &self.upstreams {
            if !seen.insert(u.host.as_str()) {
                return Err(ConfigError::DuplicateHost(u.host.clone()));
            }
        }
        self.validate_upstream_targets()?;
        self.validate_acme()
    }

    /// Each upstream must name exactly one target: a TCP `local_addr` or a Unix
    /// `local_socket`, never both and never neither.
    fn validate_upstream_targets(&self) -> Result<(), ConfigError> {
        for u in &self.upstreams {
            if u.local_addr.is_some() == u.local_socket.is_some() {
                return Err(ConfigError::UpstreamTarget(u.host.clone()));
            }
        }
        Ok(())
    }

    fn validate_acme(&self) -> Result<(), ConfigError> {
        if let Some(acme) = &self.acme
            && !acme.contact.starts_with("mailto:")
        {
            return Err(ConfigError::AcmeContact(acme.contact.clone()));
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
    fn rejects_duplicate_client_names() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000002"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::DuplicateClient(name)) if name == "a"
        ));
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
    fn parses_acme_section() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [acme]
            contact = "mailto:ops@example.com"
            cache_dir = "/var/lib/tuyau/acme"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        cfg.validate().unwrap();
        let acme = cfg.acme.unwrap();
        assert_eq!(acme.contact, "mailto:ops@example.com");
        assert!(!acme.production, "production defaults to false (staging)");
    }

    #[test]
    fn rejects_acme_contact_without_mailto() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [acme]
            contact = "ops@example.com"
            cache_dir = "/var/lib/tuyau/acme"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        match cfg.validate() {
            Err(ConfigError::AcmeContact(c)) => assert_eq!(c, "ops@example.com"),
            other => panic!("expected AcmeContact, got {other:?}"),
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

    #[cfg(feature = "dynamic")]
    #[test]
    fn validate_dynamic_relaxes_clients_but_keeps_acme() {
        // Empty clients: static rejects, dynamic allows (backend owns identity).
        let empty =
            ServerConfig::from_toml_str("listen_addr = \"127.0.0.1:4433\"\nclients = []").unwrap();
        assert!(empty.validate().is_err());
        assert!(empty.validate_dynamic().is_ok());

        // ACME contact is still validated in dynamic mode.
        let bad_acme = ServerConfig::from_toml_str(
            "listen_addr = \"127.0.0.1:4433\"\nclients = []\n\
             [acme]\ncontact = \"ops@example.com\"\ncache_dir = \"/tmp/a\"",
        )
        .unwrap();
        assert!(bad_acme.validate_dynamic().is_err());
    }
}
