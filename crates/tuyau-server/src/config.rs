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
    /// Public UDP routes: each one binds its own UDP port and forwards
    /// datagrams to a client tunnel or a local address (see [`UdpEntry`]).
    /// Empty by default — a TCP-only deployment binds no UDP socket beyond the
    /// QUIC tunnel itself.
    #[serde(default)]
    pub udp: Vec<UdpEntry>,
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

/// One public UDP route. UDP has no SNI and no connections, so routing is
/// **per-port**: each entry binds its own `listen_addr`, and every datagram
/// arriving there belongs to this route. `name` is the routing key on the wire
/// — the tunnel client matches it against its own `[[udp_ingress]]` to pick a
/// local service (the UDP counterpart of a hostname).
///
/// Exactly one destination: `client` (forward over that client's tunnel) or
/// `local_addr` (forward to a local service on this box, the UDP counterpart of
/// an `[[upstreams]]` entry).
///
/// Sharing one UDP port between several routes would need per-protocol payload
/// inspection (QUIC Initial SNI, DTLS SNI, WireGuard mac1) to tell the targets
/// apart. That is deliberately not implemented: a route is a port, and a
/// future matcher can only narrow a port, never widen one.
#[derive(Debug, Clone, Deserialize)]
pub struct UdpEntry {
    /// Routing key sent on every datagram; matched against the client's
    /// `[[udp_ingress]]`. Short (it is per-packet overhead) and limited to
    /// `[A-Za-z0-9._-]`.
    pub name: String,
    /// UDP socket to bind for this route. Must not collide with `listen_addr`
    /// (the QUIC tunnel) or another `[[udp]]` entry.
    pub listen_addr: SocketAddr,
    /// Client tunnel that serves this route. Exactly one of `client` /
    /// `local_addr` must be set.
    #[serde(default)]
    pub client: Option<String>,
    /// Local UDP service to forward to, instead of a tunnel. Exactly one of
    /// `client` / `local_addr` must be set.
    #[serde(default)]
    pub local_addr: Option<SocketAddr>,
    /// Drop a session after this long with no datagram in either direction.
    /// Defaults to [`DEFAULT_UDP_IDLE_TIMEOUT_SECS`]. UDP has no close, so this
    /// is the only thing that frees a session.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// Cap on concurrent sessions for this route. Past it, datagrams from new
    /// peers are dropped rather than growing the table — source addresses are
    /// spoofable, so the table must be bounded. Defaults to
    /// [`DEFAULT_UDP_MAX_SESSIONS`].
    #[serde(default)]
    pub max_sessions: Option<usize>,
    /// How many bytes may be sent toward a peer per byte received from it,
    /// before the session shows evidence of a round trip. Defaults to
    /// [`DEFAULT_UDP_AMPLIFICATION_FACTOR`], the same bound QUIC applies to an
    /// unvalidated path.
    ///
    /// Source addresses are forgeable, so this is what stops the port being
    /// used to reflect amplified traffic at a spoofed victim. It only ever
    /// constrains the *first* exchange: once the peer sends again after a reply
    /// the limit lifts, so long-lived and download-heavy sessions are
    /// unaffected.
    ///
    /// Protocols whose first response dwarfs its request (DNS is the classic —
    /// and the classic amplifier) need this raised to work at all. Raising it
    /// to N means accepting that the port can amplify N× toward a spoofed
    /// address; that is a deliberate trade, so it is spelled out in config
    /// rather than inferred.
    #[serde(default)]
    pub amplification_factor: Option<u64>,
}

/// Default UDP session idle timeout. Comfortably above WireGuard's 25s
/// persistent-keepalive so an idle-but-alive tunnel is never reaped.
pub const DEFAULT_UDP_IDLE_TIMEOUT_SECS: u64 = 120;

/// Default cap on concurrent sessions per UDP route.
pub const DEFAULT_UDP_MAX_SESSIONS: usize = 4096;

/// Default anti-amplification factor, matching QUIC's unvalidated-path limit.
pub const DEFAULT_UDP_AMPLIFICATION_FACTOR: u64 = 3;

impl UdpEntry {
    /// Configured idle timeout, or the default.
    pub fn idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.idle_timeout_secs
                .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECS),
        )
    }

    /// Configured session cap, or the default.
    pub fn max_sessions(&self) -> usize {
        self.max_sessions.unwrap_or(DEFAULT_UDP_MAX_SESSIONS)
    }

    /// Configured anti-amplification factor, or the default.
    pub fn amplification_factor(&self) -> u64 {
        self.amplification_factor
            .unwrap_or(DEFAULT_UDP_AMPLIFICATION_FACTOR)
    }
}

impl ServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // A server must route *something* — at least one tunnel client, one
        // static local upstream, or one UDP route (a front-only deployment has
        // no clients).
        if self.clients.is_empty() && self.upstreams.is_empty() && self.udp.is_empty() {
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
        for u in &self.udp {
            if let Some(client) = &u.client
                && !known_clients.contains(client.as_str())
            {
                return Err(ConfigError::UnknownClient {
                    host: u.name.clone(),
                    client: client.clone(),
                });
            }
        }

        self.validate_udp()?;
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
        self.validate_udp()?;
        self.validate_acme()
    }

    /// UDP routes: unique names, unique listen ports, exactly one destination,
    /// and a name that fits the per-datagram header.
    ///
    /// The port checks matter because a collision is silent otherwise: two
    /// routes on one port means whichever bound first swallows the other's
    /// traffic, and sharing the QUIC tunnel's port would eat the tunnel.
    fn validate_udp(&self) -> Result<(), ConfigError> {
        let mut seen_names: HashSet<&str> = HashSet::new();
        let mut seen_ports: HashSet<SocketAddr> = HashSet::new();
        for u in &self.udp {
            if !seen_names.insert(u.name.as_str()) {
                return Err(ConfigError::DuplicateUdpRoute(u.name.clone()));
            }
            if u.name.is_empty()
                || u.name.len() > tuyau_protocol::MAX_UDP_ROUTE_LEN
                || !u
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(ConfigError::UdpRouteName(u.name.clone()));
            }
            if u.client.is_some() == u.local_addr.is_some() {
                return Err(ConfigError::UdpTarget(u.name.clone()));
            }
            // Port 0 means "any free port", so two of them never collide —
            // only concrete ports can be compared.
            if u.listen_addr.port() != 0 {
                if u.listen_addr == self.listen_addr {
                    return Err(ConfigError::UdpPortConflictsWithTunnel(u.name.clone()));
                }
                if !seen_ports.insert(u.listen_addr) {
                    return Err(ConfigError::DuplicateUdpListenAddr(u.listen_addr));
                }
            }
        }
        Ok(())
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

    const TOK: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn udp_toml(body: &str) -> String {
        format!(
            "listen_addr = \"0.0.0.0:4433\"\n\
             [[clients]]\nname = \"a\"\ntoken = \"{TOK}\"\n{body}"
        )
    }

    #[test]
    fn parses_udp_routes() {
        let cfg = ServerConfig::from_toml_str(&udp_toml(
            "[[udp]]\n\
             name = \"wireguard\"\n\
             listen_addr = \"0.0.0.0:443\"\n\
             client = \"a\"\n\
             [[udp]]\n\
             name = \"dns\"\n\
             listen_addr = \"0.0.0.0:5353\"\n\
             local_addr = \"127.0.0.1:53\"\n\
             idle_timeout_secs = 30\n\
             max_sessions = 64\n\
             amplification_factor = 20\n",
        ))
        .unwrap();
        cfg.validate().unwrap();

        assert_eq!(cfg.udp.len(), 2);
        assert_eq!(cfg.udp[0].client.as_deref(), Some("a"));
        // Unset knobs fall back to the documented defaults.
        assert_eq!(
            cfg.udp[0].idle_timeout().as_secs(),
            DEFAULT_UDP_IDLE_TIMEOUT_SECS
        );
        assert_eq!(cfg.udp[0].max_sessions(), DEFAULT_UDP_MAX_SESSIONS);
        assert_eq!(
            cfg.udp[0].amplification_factor(),
            DEFAULT_UDP_AMPLIFICATION_FACTOR
        );
        assert_eq!(cfg.udp[1].idle_timeout().as_secs(), 30);
        assert_eq!(cfg.udp[1].max_sessions(), 64);
        assert_eq!(cfg.udp[1].amplification_factor(), 20);
    }

    #[test]
    fn a_udp_route_needs_exactly_one_destination() {
        for dest in [
            "",                                                // neither
            "client = \"a\"\nlocal_addr = \"127.0.0.1:53\"\n", // both
        ] {
            let cfg = ServerConfig::from_toml_str(&udp_toml(&format!(
                "[[udp]]\nname = \"wg\"\nlisten_addr = \"0.0.0.0:443\"\n{dest}"
            )))
            .unwrap();
            assert!(
                matches!(cfg.validate(), Err(ConfigError::UdpTarget(n)) if n == "wg"),
                "destination spec {dest:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_duplicate_udp_route_names() {
        let cfg = ServerConfig::from_toml_str(&udp_toml(
            "[[udp]]\nname = \"wg\"\nlisten_addr = \"0.0.0.0:443\"\nclient = \"a\"\n\
             [[udp]]\nname = \"wg\"\nlisten_addr = \"0.0.0.0:444\"\nclient = \"a\"\n",
        ))
        .unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::DuplicateUdpRoute(n)) if n == "wg"
        ));
    }

    #[test]
    fn rejects_two_udp_routes_on_one_port() {
        // Silent otherwise: whichever bound first would swallow the other's
        // traffic, since UDP routing here is per-port.
        let cfg = ServerConfig::from_toml_str(&udp_toml(
            "[[udp]]\nname = \"a1\"\nlisten_addr = \"0.0.0.0:443\"\nclient = \"a\"\n\
             [[udp]]\nname = \"a2\"\nlisten_addr = \"0.0.0.0:443\"\nclient = \"a\"\n",
        ))
        .unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::DuplicateUdpListenAddr(_))
        ));
    }

    #[test]
    fn rejects_a_udp_route_on_the_quic_tunnel_port() {
        // The tunnel itself is UDP; a route sharing its socket would eat it.
        let cfg = ServerConfig::from_toml_str(&udp_toml(
            "[[udp]]\nname = \"wg\"\nlisten_addr = \"0.0.0.0:4433\"\nclient = \"a\"\n",
        ))
        .unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::UdpPortConflictsWithTunnel(n)) if n == "wg"
        ));
    }

    #[test]
    fn port_zero_udp_routes_never_collide() {
        // Port 0 is "any free port", so the kernel guarantees distinctness —
        // comparing the literal addresses would reject valid (test) configs.
        let cfg = ServerConfig::from_toml_str(
            "listen_addr = \"127.0.0.1:0\"\n\
             [[clients]]\nname = \"a\"\ntoken = \"0000000000000000000000000000000000000000000000000000000000000001\"\n\
             [[udp]]\nname = \"x\"\nlisten_addr = \"127.0.0.1:0\"\nclient = \"a\"\n\
             [[udp]]\nname = \"y\"\nlisten_addr = \"127.0.0.1:0\"\nclient = \"a\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_udp_route_names_that_cannot_ride_a_datagram() {
        for name in ["", "has space", "sla/sh", &"r".repeat(65)] {
            let cfg = ServerConfig::from_toml_str(&udp_toml(&format!(
                "[[udp]]\nname = \"{name}\"\nlisten_addr = \"0.0.0.0:443\"\nclient = \"a\"\n"
            )))
            .unwrap();
            assert!(
                matches!(cfg.validate(), Err(ConfigError::UdpRouteName(_))),
                "route name {name:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_udp_route_referencing_an_unknown_client() {
        let cfg = ServerConfig::from_toml_str(&udp_toml(
            "[[udp]]\nname = \"wg\"\nlisten_addr = \"0.0.0.0:443\"\nclient = \"ghost\"\n",
        ))
        .unwrap();
        assert!(matches!(
            cfg.validate(),
            Err(ConfigError::UnknownClient { client, .. }) if client == "ghost"
        ));
    }

    #[test]
    fn a_udp_only_server_routes_something() {
        // No clients and no upstreams, but a local UDP route: that is a valid
        // front-only deployment, not an empty one.
        let cfg = ServerConfig::from_toml_str(
            "listen_addr = \"0.0.0.0:4433\"\nclients = []\n\
             [[udp]]\nname = \"dns\"\nlisten_addr = \"0.0.0.0:5353\"\nlocal_addr = \"127.0.0.1:53\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();

        // Truly empty is still rejected.
        let empty =
            ServerConfig::from_toml_str("listen_addr = \"0.0.0.0:4433\"\nclients = []").unwrap();
        assert!(matches!(empty.validate(), Err(ConfigError::NoClients)));
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
