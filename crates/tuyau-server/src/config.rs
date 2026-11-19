use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

pub use tuyau_protocol::TlsMode;

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    #[serde(default)]
    pub public_listen_addr: Option<SocketAddr>,
    pub tunnel_cert_dir: Option<PathBuf>,
    #[serde(default)]
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
    /// for the terminated hostnames without a cert of their own, instead of a
    /// self-signed one. Useful for a cert obtained out-of-band (e.g. Let's
    /// Encrypt via DNS-01) when inbound TLS-ALPN-01 validation isn't possible.
    /// Requires `tls_key_file` too.
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
    /// Optional PEM CA bundle. When set, a host the server terminates TLS for
    /// accepts only a client cert signed by it, e.g. the Cloudflare origin-pull
    /// CA, so a client cannot bypass the proxy. A passthrough host is not
    /// checked: the server does not take part in its handshake. An ACME
    /// challenge passes without a client cert.
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
    /// The cert sources of the terminated hostnames. A `[[hostnames]]` or
    /// `[[upstreams]]` entry names one with `issuer`; the others take the one
    /// with `default = true`, else a self-signed cert. Excludes `acme` and
    /// `tls_cert_file`, which stay as a short form of one default issuer.
    #[serde(default)]
    pub issuers: Vec<IssuerEntry>,
}

/// A hostname that the server terminates TLS for, given through the dynamic
/// seam, and the issuer of its cert (`None` takes the default issuer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminatedHost {
    pub host: String,
    pub issuer: Option<String>,
}

/// A named cert source.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct IssuerEntry {
    pub name: String,
    #[serde(default)]
    pub default: bool,
    #[serde(flatten)]
    pub kind: IssuerKind,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IssuerKind {
    /// A CA whose key is on this machine and that the clients trust. The
    /// server signs a cert for each hostname at its first handshake. The key
    /// is PKCS#8 (`BEGIN PRIVATE KEY`): convert a SEC1 key with
    /// `openssl pkcs8 -topk8 -nocrypt`.
    LocalCa {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    /// Let's Encrypt via TLS-ALPN-01, for names, not `*` patterns.
    Acme(AcmeSection),
    /// A PEM chain and its key obtained elsewhere (DNS-01, an origin cert).
    Imported {
        cert_file: PathBuf,
        key_file: PathBuf,
    },
    /// A self-signed cert per hostname, issued at its first handshake.
    SelfSigned,
}

/// ACME / Let's Encrypt parameters. The default `directory_url` points at LE
/// **staging** (rate-limit-friendly, untrusted certs) — flip `production` to
/// true for real Let's Encrypt certs. `contact` is the email the CA notifies
/// for expiry / policy issues.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
    /// Optional cert of this hostname, served instead of the server-wide one
    /// (`acme`, `tls_cert_file` or self-signed). Terminating modes only.
    #[serde(default)]
    pub tls_cert_file: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_file: Option<PathBuf>,
    /// Name of the issuer of its cert; `None` takes the default issuer.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// A static local upstream: a hostname served by forwarding to a local address
/// instead of a client tunnel. `host` can also be `*.example.com` (one label
/// under `example.com`) or `*` (every host that no other entry names); an
/// exact entry wins over a wildcard, and a wildcard over `*`. Lets the server front existing local services —
/// e.g. route `db.example.com` to `127.0.0.1:8443`. `tls_mode` picks how TLS is
/// handled:
/// - `passthrough` forwards the raw TLS bytes (the upstream terminates its own
///   TLS, so this box never sees plaintext);
/// - `terminated` has the server terminate TLS (it must hold a cert for the
///   host) and reverse-proxy the decrypted **HTTP** to the upstream;
/// - `tls_offload` terminates TLS the same way but byte-pipes the **plaintext**
///   with no HTTP parsing — for a cleartext non-HTTP upstream (Postgres,
///   Redis, MQTT…) that should not deal with certificates itself.
///
/// Local upstreams win over tunnel routes for the same host, so a dynamic
/// client can't hijack one.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamEntry {
    pub host: String,
    /// Forward to a local TCP address. Exactly one of `local_addr`,
    /// `local_socket` and `internal_listener` must be set.
    #[serde(default)]
    pub local_addr: Option<SocketAddr>,
    /// Forward to a local Unix domain socket (e.g. `/run/tuyau/app.sock`).
    #[serde(default)]
    pub local_socket: Option<PathBuf>,
    /// Forward to the [`InternalListener`](crate::InternalListener) of this
    /// name, in the same process. Only with [`TunnelServer::start_with`](crate::TunnelServer).
    #[serde(default)]
    pub internal_listener: Option<String>,
    #[serde(default)]
    pub tls_mode: TlsMode,
    /// Optional cert of this hostname, as in [`HostnameEntry`].
    #[serde(default)]
    pub tls_cert_file: Option<PathBuf>,
    #[serde(default)]
    pub tls_key_file: Option<PathBuf>,
    /// Name of the issuer of its cert, as in [`HostnameEntry`].
    #[serde(default)]
    pub issuer: Option<String>,
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
        if let Some(u) = self
            .upstreams
            .iter()
            .find(|u| u.internal_listener.is_some())
        {
            return Err(ConfigError::InternalListenerStatic(u.host.clone()));
        }
        self.validate_host_patterns()?;
        self.validate_host_certs()?;

        let known_clients: HashSet<&str> = self.clients.iter().map(|c| c.name.as_str()).collect();
        for h in &self.hostnames {
            if !known_clients.contains(h.client.as_str()) {
                return Err(ConfigError::UnknownClient {
                    host: h.host.clone(),
                    client: h.client.clone(),
                });
            }
        }

        self.validate_acme()?;
        self.validate_issuers(IssuerNames::Configured)
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
        self.validate_host_patterns()?;
        self.validate_host_certs()?;
        self.validate_acme()?;
        self.validate_issuers(IssuerNames::SetLater)
    }

    /// Each upstream names exactly one target.
    fn validate_upstream_targets(&self) -> Result<(), ConfigError> {
        for u in &self.upstreams {
            let targets = [
                u.local_addr.is_some(),
                u.local_socket.is_some(),
                u.internal_listener.is_some(),
            ];
            if targets.into_iter().filter(|set| *set).count() != 1 {
                return Err(ConfigError::UpstreamTarget(u.host.clone()));
            }
        }
        Ok(())
    }

    /// An upstream host is a name, `*.name` or `*`; a tunnel hostname is a name.
    fn validate_host_patterns(&self) -> Result<(), ConfigError> {
        for h in &self.hostnames {
            if h.host.contains('*') {
                return Err(ConfigError::HostPattern(h.host.clone()));
            }
        }

        for u in &self.upstreams {
            let name = match u.host.as_str() {
                "*" => continue,
                host => host.strip_prefix("*.").unwrap_or(host),
            };

            if name.is_empty() || name.contains('*') {
                return Err(ConfigError::HostPattern(u.host.clone()));
            }
        }

        Ok(())
    }

    /// The (host, mode, cert, key) of each hostname and upstream entry.
    pub(crate) fn host_certs(
        &self,
    ) -> impl Iterator<Item = (&str, TlsMode, &Option<PathBuf>, &Option<PathBuf>)> {
        let hostnames = self.hostnames.iter().map(|h| {
            (
                h.host.as_str(),
                h.tls_mode,
                &h.tls_cert_file,
                &h.tls_key_file,
            )
        });
        let upstreams = self.upstreams.iter().map(|u| {
            (
                u.host.as_str(),
                u.tls_mode,
                &u.tls_cert_file,
                &u.tls_key_file,
            )
        });

        hostnames.chain(upstreams)
    }

    /// A cert of an entry comes with its key, and only in a mode where the
    /// server terminates TLS: a passthrough host never uses a cert here.
    fn validate_host_certs(&self) -> Result<(), ConfigError> {
        for (host, mode, cert, key) in self.host_certs() {
            if cert.is_some() != key.is_some() {
                return Err(ConfigError::HostCertPair(host.to_string()));
            }

            if cert.is_some() && mode == TlsMode::Passthrough {
                return Err(ConfigError::HostCertPassthrough(host.to_string()));
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

    /// The issuers in force: `issuers`, else one default issuer for `acme` or
    /// `tls_cert_file`, else none (a self-signed cert per hostname).
    pub fn effective_issuers(&self) -> Vec<IssuerEntry> {
        if !self.issuers.is_empty() {
            return self.issuers.clone();
        }

        if let Some(acme) = &self.acme {
            return vec![IssuerEntry {
                name: "acme".into(),
                default: true,
                kind: IssuerKind::Acme(acme.clone()),
            }];
        }

        if let (Some(cert_file), Some(key_file)) = (&self.tls_cert_file, &self.tls_key_file) {
            return vec![IssuerEntry {
                name: "tls_cert_file".into(),
                default: true,
                kind: IssuerKind::Imported {
                    cert_file: cert_file.clone(),
                    key_file: key_file.clone(),
                },
            }];
        }

        Vec::new()
    }

    /// The (host, mode, own cert, issuer) of each entry that names an issuer.
    pub(crate) fn host_issuers(&self) -> impl Iterator<Item = (&str, TlsMode, bool, &str)> {
        let hostnames = self.hostnames.iter().filter_map(|h| {
            let issuer = h.issuer.as_deref()?;
            Some((
                h.host.as_str(),
                h.tls_mode,
                h.tls_cert_file.is_some(),
                issuer,
            ))
        });
        let upstreams = self.upstreams.iter().filter_map(|u| {
            let issuer = u.issuer.as_deref()?;
            Some((
                u.host.as_str(),
                u.tls_mode,
                u.tls_cert_file.is_some(),
                issuer,
            ))
        });

        hostnames.chain(upstreams)
    }

    fn validate_issuers(&self, names: IssuerNames) -> Result<(), ConfigError> {
        let legacy =
            self.acme.is_some() || self.tls_cert_file.is_some() || self.tls_key_file.is_some();

        if !self.issuers.is_empty() && legacy {
            return Err(ConfigError::IssuersWithLegacy);
        }

        validate_issuer_list(&self.issuers)?;
        let issuers = self.effective_issuers();

        for (host, mode, own_cert, name) in self.host_issuers() {
            if mode == TlsMode::Passthrough {
                return Err(ConfigError::IssuerPassthrough(host.to_string()));
            }

            if own_cert {
                return Err(ConfigError::IssuerWithCert(host.to_string()));
            }

            let Some(issuer) = issuers.iter().find(|i| i.name == name) else {
                if names == IssuerNames::SetLater {
                    continue;
                }

                return Err(ConfigError::UnknownIssuer {
                    host: host.to_string(),
                    issuer: name.to_string(),
                });
            };

            if host.contains('*') && matches!(issuer.kind, IssuerKind::Acme(_)) {
                return Err(ConfigError::AcmePattern(host.to_string()));
            }
        }

        Ok(())
    }
}

/// Where the issuer names of the entries come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssuerNames {
    /// `issuers` holds them all.
    Configured,
    /// The dynamic seam sets the issuers after the start: an unknown name
    /// takes the default issuer until one with that name arrives.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    SetLater,
}

/// Names are unique, at most one issuer is the default, and an ACME contact is
/// a `mailto:` URL.
pub(crate) fn validate_issuer_list(issuers: &[IssuerEntry]) -> Result<(), ConfigError> {
    let mut names: HashSet<&str> = HashSet::new();

    for issuer in issuers {
        if !names.insert(issuer.name.as_str()) {
            return Err(ConfigError::DuplicateIssuer(issuer.name.clone()));
        }

        if let IssuerKind::Acme(acme) = &issuer.kind
            && !acme.contact.starts_with("mailto:")
        {
            return Err(ConfigError::AcmeContact(acme.contact.clone()));
        }
    }

    if issuers.iter().filter(|i| i.default).count() > 1 {
        return Err(ConfigError::DefaultIssuers);
    }

    Ok(())
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
    fn parses_tls_offload_mode() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "db.example.com"
            client = "a"
            tls_mode = "tls_offload"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.hostnames[0].tls_mode, TlsMode::TlsOffload);
    }

    #[test]
    fn a_front_with_upstreams_only_needs_no_clients_key() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[upstreams]]
            host = "a.example.com"
            local_addr = "127.0.0.1:1"
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();

        assert!(cfg.clients.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_no_clients_and_no_upstreams() {
        let toml = r#"listen_addr = "0.0.0.0:4433""#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert!(matches!(cfg.validate(), Err(ConfigError::NoClients)));
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
    fn a_host_cert_needs_its_key_and_a_terminating_mode() {
        let upstream = |extra: &str| {
            let toml = format!(
                "listen_addr = \"0.0.0.0:4433\"\nclients = []\n\
                 [[upstreams]]\nhost = \"a.example.com\"\nlocal_addr = \"127.0.0.1:1\"\n{extra}"
            );
            ServerConfig::from_toml_str(&toml).unwrap().validate()
        };

        let pair = "tls_cert_file = \"a.crt\"\ntls_key_file = \"a.key\"\n";

        assert!(upstream(pair).is_ok());
        assert!(upstream(&format!("tls_mode = \"tls_offload\"\n{pair}")).is_ok());
        assert!(matches!(
            upstream("tls_cert_file = \"a.crt\"\n"),
            Err(ConfigError::HostCertPair(host)) if host == "a.example.com"
        ));
        assert!(matches!(
            upstream("tls_key_file = \"a.key\"\n"),
            Err(ConfigError::HostCertPair(_))
        ));
        assert!(matches!(
            upstream(&format!("tls_mode = \"passthrough\"\n{pair}")),
            Err(ConfigError::HostCertPassthrough(_))
        ));
    }

    #[test]
    fn an_upstream_host_is_a_name_a_one_label_wildcard_or_the_catch_all() {
        let upstream = |host: &str| {
            let toml = format!(
                "listen_addr = \"0.0.0.0:4433\"\n[[upstreams]]\nhost = \"{host}\"\nlocal_addr = \"127.0.0.1:1\"\n"
            );
            ServerConfig::from_toml_str(&toml).unwrap().validate()
        };

        for host in ["a.example.com", "*.example.com", "*"] {
            assert!(upstream(host).is_ok(), "{host}");
        }

        for host in [
            "*.",
            "**",
            "a.*.example.com",
            "*.*.example.com",
            "*example.com",
        ] {
            assert!(
                matches!(upstream(host), Err(ConfigError::HostPattern(_))),
                "{host}"
            );
        }
    }

    #[test]
    fn a_tunnel_hostname_cannot_be_a_pattern() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "*.example.com"
            client = "a"
        "#;

        let config = ServerConfig::from_toml_str(toml).unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::HostPattern(_))
        ));
    }

    #[test]
    fn a_hostname_entry_takes_a_cert_too() {
        let toml = r#"
            listen_addr = "0.0.0.0:4433"
            [[clients]]
            name = "a"
            token = "0000000000000000000000000000000000000000000000000000000000000001"
            [[hostnames]]
            host = "a.example.com"
            client = "a"
            tls_cert_file = "a.crt"
        "#;

        let config = ServerConfig::from_toml_str(toml).unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::HostCertPair(_))
        ));
    }

    const ISSUERS: &str = r#"
        [[issuers]]
        name = "home"
        kind = "local_ca"
        cert_file = "ca.pem"
        key_file = "ca.key"
        default = true

        [[issuers]]
        name = "le"
        kind = "acme"
        contact = "mailto:ops@example.com"
        cache_dir = "/tmp/acme"

        [[issuers]]
        name = "origin"
        kind = "imported"
        cert_file = "o.pem"
        key_file = "o.key"

        [[issuers]]
        name = "dev"
        kind = "self_signed"
    "#;

    /// A config with the four issuers and one upstream with `entry` lines.
    fn with_issuers(top: &str, host: &str, entry: &str) -> Result<ServerConfig, ConfigError> {
        let toml = format!(
            "listen_addr = \"0.0.0.0:4433\"\n{top}\n{ISSUERS}\n\
             [[upstreams]]\nhost = \"{host}\"\nlocal_addr = \"127.0.0.1:1\"\n{entry}\n"
        );
        let config = ServerConfig::from_toml_str(&toml)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn parses_the_four_issuer_kinds() {
        let config = with_issuers("", "a.example.com", "issuer = \"le\"").unwrap();

        assert_eq!(config.issuers.len(), 4);
        assert!(config.issuers[0].default);
        assert!(matches!(config.issuers[1].kind, IssuerKind::Acme(_)));
        assert_eq!(config.issuers[3].kind, IssuerKind::SelfSigned);
        assert_eq!(config.upstreams[0].issuer.as_deref(), Some("le"));
    }

    #[test]
    fn an_entry_names_a_known_issuer_in_a_mode_and_a_form_that_take_it() {
        assert!(matches!(
            with_issuers("", "a.example.com", "issuer = \"nope\""),
            Err(ConfigError::UnknownIssuer { issuer, .. }) if issuer == "nope"
        ));
        assert!(matches!(
            with_issuers(
                "",
                "a.example.com",
                "tls_mode = \"passthrough\"\nissuer = \"home\""
            ),
            Err(ConfigError::IssuerPassthrough(_))
        ));
        assert!(matches!(
            with_issuers(
                "",
                "a.example.com",
                "issuer = \"home\"\ntls_cert_file = \"a.crt\"\ntls_key_file = \"a.key\""
            ),
            Err(ConfigError::IssuerWithCert(_))
        ));
        assert!(matches!(
            with_issuers("", "*.example.com", "issuer = \"le\""),
            Err(ConfigError::AcmePattern(_))
        ));
        assert!(with_issuers("", "*.example.com", "issuer = \"home\"").is_ok());
    }

    #[test]
    fn issuers_exclude_their_short_form() {
        assert!(matches!(
            with_issuers(
                "tls_cert_file = \"a.crt\"\ntls_key_file = \"a.key\"",
                "a.example.com",
                ""
            ),
            Err(ConfigError::IssuersWithLegacy)
        ));
    }

    #[test]
    fn issuer_names_are_unique_and_one_at_most_is_the_default() {
        let issuer = |name: &str, default: bool| IssuerEntry {
            name: name.into(),
            default,
            kind: IssuerKind::SelfSigned,
        };

        assert!(validate_issuer_list(&[issuer("a", true), issuer("b", false)]).is_ok());
        assert!(matches!(
            validate_issuer_list(&[issuer("a", false), issuer("a", false)]),
            Err(ConfigError::DuplicateIssuer(_))
        ));
        assert!(matches!(
            validate_issuer_list(&[issuer("a", true), issuer("b", true)]),
            Err(ConfigError::DefaultIssuers)
        ));
    }

    #[test]
    fn acme_and_tls_cert_file_are_a_default_issuer() {
        let config = |top: &str| {
            let toml = format!(
                "listen_addr = \"0.0.0.0:4433\"\n{top}\n\
                 [[upstreams]]\nhost = \"a.example.com\"\nlocal_addr = \"127.0.0.1:1\"\n"
            );
            ServerConfig::from_toml_str(&toml).unwrap()
        };

        let acme = config("[acme]\ncontact = \"mailto:ops@example.com\"\ncache_dir = \"/tmp/a\"");
        let file = config("tls_cert_file = \"a.crt\"\ntls_key_file = \"a.key\"");

        assert!(matches!(
            acme.effective_issuers()[..],
            [IssuerEntry {
                default: true,
                kind: IssuerKind::Acme(_),
                ..
            }]
        ));
        assert!(matches!(
            file.effective_issuers()[..],
            [IssuerEntry {
                default: true,
                kind: IssuerKind::Imported { .. },
                ..
            }]
        ));
        assert!(config("").effective_issuers().is_empty());
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
    fn a_dynamic_server_takes_an_issuer_name_that_arrives_after_the_start() {
        let config = ServerConfig::from_toml_str(
            "listen_addr = \"127.0.0.1:4433\"\n\
             [[upstreams]]\nhost = \"a.example.com\"\nlocal_addr = \"127.0.0.1:1\"\nissuer = \"later\"",
        )
        .unwrap();

        assert!(config.validate_dynamic().is_ok());
        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnknownIssuer { .. })
        ));
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
