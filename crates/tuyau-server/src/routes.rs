use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// parking_lot locks DON'T poison: if a thread panics while holding a guard, the
// next acquirer still gets the lock (with whatever state was left — always a
// valid map, never UB). A std lock would poison and every later `.expect()`
// would panic, cascading one stray panic into "all routing dead" — which would
// take down everything this server fronts. Never reintroduce a poisoning lock here.
use parking_lot::RwLock;

use crate::config::{Balance, HostnameEntry, TlsMode, UpstreamEntry};

/// A single resolved tunnel route: the connection chosen to serve one public
/// connection, plus the metadata the public listener needs.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub client_name: String,
    pub tls_mode: TlsMode,
    pub conn: quinn::Connection,
}

/// The destination of a local upstream: a TCP address or a Unix socket path.
#[derive(Debug, Clone)]
pub enum UpstreamTarget {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

/// Where a hostname's public traffic goes: a client tunnel, or a static local
/// upstream the server forwards to directly. Whether to terminate TLS is decided
/// separately, from the routing table's terminated set ([`RoutingTable::is_terminated`]).
#[derive(Debug, Clone)]
pub enum Route {
    Tunnel(RouteEntry),
    Local { target: UpstreamTarget },
}

/// A static local upstream resolved for a hostname (from [`UpstreamEntry`]).
#[derive(Debug, Clone)]
struct LocalUpstream {
    target: UpstreamTarget,
}

/// All tunnels currently serving one hostname. A hostname is owned by exactly
/// one client (identity) at a time: with `last-write-wins` there is ever only
/// one connection; with `round-robin` there may be several from the *same*
/// client (active-active), and `cursor` spreads public connections across them.
/// A grant from a different client takes the host over entirely (see `install`).
#[derive(Debug)]
struct HostRoutes {
    client_name: String,
    tls_mode: TlsMode,
    conns: Vec<quinn::Connection>,
    cursor: AtomicUsize,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    inner: Arc<RwLock<HashMap<String, HostRoutes>>>,
    /// Static local upstreams, fixed at construction (never change at runtime,
    /// unlike tunnel routes). Take precedence over tunnels in `lookup`.
    local: Arc<HashMap<String, LocalUpstream>>,
    /// Hostnames the server terminates TLS for — the KNOWN set (config + the
    /// dynamic seam). The public listener decides "terminate this SNI?" from
    /// this (so an ACME challenge / the cert is served regardless of whether a
    /// tunnel is currently routed), and the ACME domain list mirrors it.
    terminated: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl RoutingTable {
    /// Build a table from config: static local upstreams + the terminated-set
    /// seed. Config validation guarantees each upstream names exactly one target;
    /// an entry with neither is defensively skipped. In dynamic mode `hostnames`
    /// is empty (the backend owns them) and the seam seeds the terminated set.
    pub fn from_config(hostnames: &[HostnameEntry], upstreams: &[UpstreamEntry]) -> Self {
        let local = upstreams
            .iter()
            .filter_map(|u| {
                let target = match (&u.local_socket, u.local_addr) {
                    (Some(path), _) => UpstreamTarget::Unix(path.clone()),
                    (None, Some(addr)) => UpstreamTarget::Tcp(addr),
                    (None, None) => return None,
                };
                Some((u.host.clone(), LocalUpstream { target }))
            })
            .collect();
        // Seed the terminated set with every terminated hostname known from
        // config — tunnel-routed (`hostnames`) AND local upstreams.
        let terminated = hostnames
            .iter()
            .filter(|h| h.tls_mode == TlsMode::Terminated)
            .map(|h| h.host.to_ascii_lowercase())
            .chain(
                upstreams
                    .iter()
                    .filter(|u| u.tls_mode == TlsMode::Terminated)
                    .map(|u| u.host.to_ascii_lowercase()),
            )
            .collect();
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            local: Arc::new(local),
            terminated: Arc::new(RwLock::new(terminated)),
        }
    }

    /// Whether the server terminates TLS for `host` (it's in the known set).
    /// Case-insensitive — DNS hostnames are, and clients/LE lowercase the SNI.
    pub fn is_terminated(&self, host: &str) -> bool {
        self.terminated.read().contains(&host.to_ascii_lowercase())
    }

    /// Replace the whole terminated set. The caller (the dynamic seam) passes the
    /// full set it knows (config-terminated ∪ backend-provisioned terminated).
    #[cfg(feature = "dynamic")]
    pub fn set_terminated(&self, full: Vec<String>) {
        let mut g = self.terminated.write();
        *g = full.into_iter().map(|s| s.to_ascii_lowercase()).collect();
    }

    /// Install routes for a freshly authenticated connection, applying the
    /// client's `balance` policy:
    ///
    /// - `LastWriteWins`: the new connection replaces any previous ones for
    ///   each host; the displaced connections are returned so the caller can
    ///   close them.
    /// - `RoundRobin`: the new connection is *added* to each host's set and
    ///   coexists with the others; nothing is displaced.
    ///
    /// Returns the connections that were displaced (empty under `RoundRobin`,
    /// or when nothing was holding the hosts yet).
    pub fn install(
        &self,
        hosts: Vec<(String, TlsMode)>,
        client_name: &str,
        balance: Balance,
        conn: &quinn::Connection,
    ) -> Vec<quinn::Connection> {
        if hosts.is_empty() {
            return Vec::new();
        }

        let mut guard = self.inner.write();
        let new_id = conn.stable_id();
        let mut displaced: Vec<quinn::Connection> = Vec::new();

        for (host, tls_mode) in hosts {
            let entry = guard.entry(host).or_insert_with(|| HostRoutes {
                client_name: client_name.to_string(),
                tls_mode,
                conns: Vec::new(),
                cursor: AtomicUsize::new(0),
            });

            // A grant from a *different* client takes the hostname over
            // entirely: connections from two identities must never coexist under
            // one host (round-robin would cross-route traffic between them, and
            // last-write-wins would silently kick the rightful owner with no
            // takeover semantics). Evict the incumbent's connections. In static
            // mode config validation guarantees one client per host, so this
            // only fires for a dynamic backend reassigning a host.
            if entry.client_name != client_name {
                tracing::warn!(
                    previous_client = %entry.client_name,
                    new_client = %client_name,
                    "hostname reassigned to a different client; evicting previous owner's tunnels"
                );
                displaced.append(&mut entry.conns);
                entry.client_name = client_name.to_string();
            }
            entry.tls_mode = tls_mode;

            match balance {
                Balance::LastWriteWins => {
                    for c in entry.conns.drain(..) {
                        if c.stable_id() != new_id {
                            displaced.push(c);
                        }
                    }
                    entry.conns.push(conn.clone());
                }
                Balance::RoundRobin => {
                    if !entry.conns.iter().any(|c| c.stable_id() == new_id) {
                        entry.conns.push(conn.clone());
                    }
                }
            }
        }

        displaced
    }

    /// Remove every connection matching `stable_id` from all hosts, dropping
    /// any host left with no connections. Called when a tunnel closes
    /// (peer-initiated, timeout, or shutdown).
    pub fn remove_conn(&self, stable_id: usize) {
        let mut guard = self.inner.write();
        guard.retain(|_, entry| {
            entry.conns.retain(|c| c.stable_id() != stable_id);
            !entry.conns.is_empty()
        });
    }

    /// Remove every hostname owned by `client_name` and return that client's
    /// unique connections (deduplicated, since one tunnel can serve several
    /// hosts) so the caller can close them. Used for control-plane revocation.
    #[cfg(feature = "dynamic")]
    pub fn kick(&self, client_name: &str) -> Vec<quinn::Connection> {
        let mut guard = self.inner.write();
        let mut conns: Vec<quinn::Connection> = Vec::new();
        let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        guard.retain(|_, entry| {
            if entry.client_name == client_name {
                for c in &entry.conns {
                    if seen.insert(c.stable_id()) {
                        conns.push(c.clone());
                    }
                }
                false // drop this host entry
            } else {
                true
            }
        });
        conns
    }

    /// Sorted snapshot of active hostnames: those with ≥1 tunnel, plus every
    /// static local upstream.
    pub fn active_hostnames(&self) -> Vec<String> {
        let guard = self.inner.read();
        let mut hosts: Vec<String> = guard
            .keys()
            .cloned()
            .chain(self.local.keys().cloned())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Resolve `host` to a route. A static local upstream wins over any tunnel
    /// for the same host (so a dynamic client can't hijack a fronted hostname).
    /// Otherwise round-robins across the host's tunnels: successive lookups
    /// cycle through them, skipping any already known closed; if every one is
    /// dead, returns `None`.
    pub fn lookup(&self, host: &str) -> Option<Route> {
        if let Some(up) = self.local.get(host) {
            return Some(Route::Local {
                target: up.target.clone(),
            });
        }

        let guard = self.inner.read();
        let entry = guard.get(host)?;
        let n = entry.conns.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = entry.cursor.fetch_add(1, Ordering::Relaxed) % n;
            let conn = &entry.conns[idx];
            if conn.close_reason().is_none() {
                return Some(Route::Tunnel(RouteEntry {
                    client_name: entry.client_name.clone(),
                    tls_mode: entry.tls_mode,
                    conn: conn.clone(),
                }));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SPOF guard: a panic while a routing-table guard is held must NOT
    /// wedge the table. With a std (poisoning) lock the post-panic calls below
    /// would themselves panic, cascading one stray panic into "all routing dead"
    /// — and this server fronts other services. parking_lot doesn't poison, so
    /// the table keeps working. If this test ever panics, a poisoning lock was
    /// reintroduced.
    #[test]
    fn panic_while_holding_a_guard_does_not_wedge_the_table() {
        let table = RoutingTable::default();

        // Panic in another thread while holding the inner (routes) write guard.
        let t = table.clone();
        let res = std::thread::spawn(move || {
            let _g = t.inner.write();
            panic!("boom while holding the routes lock");
        })
        .join();
        assert!(res.is_err(), "the spawned thread was expected to panic");

        // Same for the terminated set.
        let t = table.clone();
        let res = std::thread::spawn(move || {
            let _g = t.terminated.write();
            panic!("boom while holding the terminated lock");
        })
        .join();
        assert!(res.is_err());

        // The table must still answer — not panic on a poisoned lock.
        assert!(table.lookup("anything.example.com").is_none());
        assert!(!table.is_terminated("anything.example.com"));
        assert!(table.active_hostnames().is_empty());
    }
}
