use async_trait::async_trait;
use subtle::ConstantTimeEq;

use crate::config::{Balance, ClientEntry, HostnameEntry, ServerConfig, TlsMode};

/// What the core needs to admit a client tunnel: who it is, how to balance
/// several tunnels of that identity, and which hostnames it serves.
pub struct ClientGrant {
    pub client_name: String,
    pub balance: Balance,
    pub hostnames: Vec<(String, TlsMode)>,
}

/// The core's sole policy input. The server calls [`RoutingBackend::admit`] when
/// a client tunnel connects; on `Some(grant)` it installs the granted routes and
/// forwards public users to that tunnel by SNI. The core knows nothing else
/// about identity or authorization.
///
/// Two implementations: [`StaticBackend`] (config-file / `server.toml`, the
/// self-host mode) and — once the `dynamic` feature exposes [`crate`] for
/// embedding — whatever the embedder (e.g. a managed control plane) injects.
#[async_trait]
pub trait RoutingBackend: Send + Sync {
    /// Decide whether a tunnel presenting `token` is admitted, and if so what it
    /// serves. `None` rejects the connection.
    async fn admit(&self, token: &[u8; 32]) -> Option<ClientGrant>;
}

/// Static, config-backed backend — the historical behaviour. The server config
/// is the source of truth for token → client and client → hostnames.
pub struct StaticBackend {
    clients: Vec<ClientEntry>,
    hostnames: Vec<HostnameEntry>,
}

impl StaticBackend {
    pub fn new(cfg: &ServerConfig) -> Self {
        Self {
            clients: cfg.clients.clone(),
            hostnames: cfg.hostnames.clone(),
        }
    }
}

#[async_trait]
impl RoutingBackend for StaticBackend {
    async fn admit(&self, token: &[u8; 32]) -> Option<ClientGrant> {
        // Constant-time comparison against every entry; the last match wins
        // (preserves the prior `match_token` behaviour).
        let mut matched: Option<&ClientEntry> = None;
        for c in &self.clients {
            if token.ct_eq(&c.token).into() {
                matched = Some(c);
            }
        }
        let client = matched?;

        let hostnames = self
            .hostnames
            .iter()
            .filter(|h| h.client == client.name)
            .map(|h| (h.host.clone(), h.tls_mode))
            .collect();

        Some(ClientGrant {
            client_name: client.name.clone(),
            balance: client.balance,
            hostnames,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOK_A: [u8; 32] = [0xAA; 32];
    const TOK_B: [u8; 32] = [0xBB; 32];
    const TOK_C: [u8; 32] = [0xCC; 32];

    fn client(name: &str, token: [u8; 32], balance: Balance) -> ClientEntry {
        ClientEntry {
            name: name.into(),
            token,
            balance,
        }
    }

    fn host(h: &str, client: &str, mode: TlsMode) -> HostnameEntry {
        HostnameEntry {
            host: h.into(),
            client: client.into(),
            tls_mode: mode,
        }
    }

    fn cfg(clients: Vec<ClientEntry>, hostnames: Vec<HostnameEntry>) -> ServerConfig {
        ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            public_listen_addr: None,
            tunnel_cert_dir: None,
            clients,
            hostnames,
            acme: None,
            tls_cert_file: None,
            tls_key_file: None,
            max_public_connections: None,
            error_502_file: None,
            upstreams: vec![],
        }
    }

    fn backend(clients: Vec<ClientEntry>, hostnames: Vec<HostnameEntry>) -> StaticBackend {
        StaticBackend::new(&cfg(clients, hostnames))
    }

    #[tokio::test]
    async fn valid_token_is_admitted_with_its_name() {
        let b = backend(vec![client("a", TOK_A, Balance::LastWriteWins)], vec![]);
        let grant = b.admit(&TOK_A).await.expect("admitted");
        assert_eq!(grant.client_name, "a");
    }

    #[tokio::test]
    async fn unknown_token_is_rejected() {
        let b = backend(vec![client("a", TOK_A, Balance::LastWriteWins)], vec![]);
        assert!(b.admit(&TOK_B).await.is_none());
    }

    #[tokio::test]
    async fn empty_client_list_rejects_everything() {
        let b = backend(vec![], vec![]);
        assert!(b.admit(&TOK_A).await.is_none());
    }

    #[tokio::test]
    async fn token_off_by_one_byte_is_rejected() {
        let mut almost = TOK_A;
        almost[31] ^= 0x01;
        let b = backend(vec![client("a", TOK_A, Balance::LastWriteWins)], vec![]);
        assert!(b.admit(&almost).await.is_none());
    }

    #[tokio::test]
    async fn default_balance_is_propagated() {
        let b = backend(vec![client("a", TOK_A, Balance::default())], vec![]);
        let grant = b.admit(&TOK_A).await.unwrap();
        assert_eq!(grant.balance, Balance::LastWriteWins);
    }

    #[tokio::test]
    async fn round_robin_balance_is_propagated() {
        let b = backend(vec![client("a", TOK_A, Balance::RoundRobin)], vec![]);
        let grant = b.admit(&TOK_A).await.unwrap();
        assert_eq!(grant.balance, Balance::RoundRobin);
    }

    #[tokio::test]
    async fn hostnames_are_filtered_to_the_owning_client() {
        let b = backend(
            vec![
                client("a", TOK_A, Balance::LastWriteWins),
                client("b", TOK_B, Balance::LastWriteWins),
            ],
            vec![
                host("a1.example", "a", TlsMode::Terminated),
                host("b1.example", "b", TlsMode::Terminated),
                host("a2.example", "a", TlsMode::Terminated),
            ],
        );
        let grant = b.admit(&TOK_A).await.unwrap();
        let hosts: Vec<&str> = grant.hostnames.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(hosts, vec!["a1.example", "a2.example"]);
    }

    #[tokio::test]
    async fn other_clients_hostnames_are_excluded() {
        let b = backend(
            vec![
                client("a", TOK_A, Balance::LastWriteWins),
                client("b", TOK_B, Balance::LastWriteWins),
            ],
            vec![host("b1.example", "b", TlsMode::Terminated)],
        );
        let grant = b.admit(&TOK_A).await.unwrap();
        assert!(grant.hostnames.is_empty(), "a owns no hostnames");
    }

    #[tokio::test]
    async fn tls_mode_is_preserved_per_hostname() {
        let b = backend(
            vec![client("a", TOK_A, Balance::LastWriteWins)],
            vec![
                host("term.example", "a", TlsMode::Terminated),
                host("pass.example", "a", TlsMode::Passthrough),
            ],
        );
        let grant = b.admit(&TOK_A).await.unwrap();
        assert_eq!(
            grant.hostnames,
            vec![
                ("term.example".to_string(), TlsMode::Terminated),
                ("pass.example".to_string(), TlsMode::Passthrough),
            ]
        );
    }

    #[tokio::test]
    async fn client_without_hostnames_is_still_admitted() {
        let b = backend(vec![client("a", TOK_A, Balance::LastWriteWins)], vec![]);
        let grant = b.admit(&TOK_A).await.expect("admitted");
        assert_eq!(grant.client_name, "a");
        assert!(grant.hostnames.is_empty());
    }

    #[tokio::test]
    async fn multiple_clients_resolve_independently() {
        let b = backend(
            vec![
                client("a", TOK_A, Balance::LastWriteWins),
                client("b", TOK_B, Balance::RoundRobin),
            ],
            vec![
                host("a.example", "a", TlsMode::Terminated),
                host("b.example", "b", TlsMode::Passthrough),
            ],
        );
        let ga = b.admit(&TOK_A).await.unwrap();
        assert_eq!(ga.client_name, "a");
        assert_eq!(ga.balance, Balance::LastWriteWins);
        assert_eq!(
            ga.hostnames,
            vec![("a.example".into(), TlsMode::Terminated)]
        );

        let gb = b.admit(&TOK_B).await.unwrap();
        assert_eq!(gb.client_name, "b");
        assert_eq!(gb.balance, Balance::RoundRobin);
        assert_eq!(
            gb.hostnames,
            vec![("b.example".into(), TlsMode::Passthrough)]
        );

        assert!(b.admit(&TOK_C).await.is_none());
    }

    #[tokio::test]
    async fn duplicate_token_last_entry_wins() {
        // Two entries share a token: the last one wins (documented behaviour).
        let b = backend(
            vec![
                client("first", TOK_A, Balance::LastWriteWins),
                client("second", TOK_A, Balance::RoundRobin),
            ],
            vec![
                host("first.example", "first", TlsMode::Terminated),
                host("second.example", "second", TlsMode::Terminated),
            ],
        );
        let grant = b.admit(&TOK_A).await.unwrap();
        assert_eq!(grant.client_name, "second");
        assert_eq!(grant.balance, Balance::RoundRobin);
        assert_eq!(
            grant.hostnames,
            vec![("second.example".to_string(), TlsMode::Terminated)]
        );
    }

    #[tokio::test]
    async fn hostname_order_is_preserved() {
        let b = backend(
            vec![client("a", TOK_A, Balance::LastWriteWins)],
            vec![
                host("z.example", "a", TlsMode::Terminated),
                host("m.example", "a", TlsMode::Terminated),
                host("a.example", "a", TlsMode::Terminated),
            ],
        );
        let grant = b.admit(&TOK_A).await.unwrap();
        let hosts: Vec<&str> = grant.hostnames.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(hosts, vec!["z.example", "m.example", "a.example"]);
    }

    #[tokio::test]
    async fn backend_snapshots_config_at_construction() {
        // new() clones; later mutating the source config must not affect it.
        let mut c = cfg(vec![client("a", TOK_A, Balance::LastWriteWins)], vec![]);
        let b = StaticBackend::new(&c);
        c.clients.clear();
        c.hostnames
            .push(host("late.example", "a", TlsMode::Terminated));
        let grant = b.admit(&TOK_A).await.expect("still admitted from snapshot");
        assert_eq!(grant.client_name, "a");
        assert!(
            grant.hostnames.is_empty(),
            "snapshot ignores later mutations"
        );
    }
}
