use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::config::{Balance, TlsMode};

/// A single resolved route: the tunnel connection chosen to serve one public
/// connection, plus the metadata the public listener needs.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub client_name: String,
    pub tls_mode: TlsMode,
    pub conn: quinn::Connection,
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
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
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

        let mut guard = self.inner.write().expect("routes lock poisoned");
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
        let mut guard = self.inner.write().expect("routes lock poisoned");
        guard.retain(|_, entry| {
            entry.conns.retain(|c| c.stable_id() != stable_id);
            !entry.conns.is_empty()
        });
    }

    /// Sorted snapshot of currently active hostnames (those with ≥1 tunnel).
    pub fn active_hostnames(&self) -> Vec<String> {
        let guard = self.inner.read().expect("routes lock poisoned");
        let mut hosts: Vec<String> = guard.keys().cloned().collect();
        hosts.sort();
        hosts
    }

    /// Resolve `host` to one tunnel connection. With multiple connections
    /// (round-robin) successive lookups cycle through them; with one it always
    /// returns that one. Used by the public listener per incoming connection.
    pub fn lookup(&self, host: &str) -> Option<RouteEntry> {
        let guard = self.inner.read().expect("routes lock poisoned");
        let entry = guard.get(host)?;
        let n = entry.conns.len();
        if n == 0 {
            return None;
        }
        // Round-robin, but skip connections already known closed (their owning
        // handler removes them shortly; this just avoids dispatching to a corpse
        // in the meantime). Try at most one full cycle; if every connection is
        // dead, drop rather than return one.
        for _ in 0..n {
            let idx = entry.cursor.fetch_add(1, Ordering::Relaxed) % n;
            let conn = &entry.conns[idx];
            if conn.close_reason().is_none() {
                return Some(RouteEntry {
                    client_name: entry.client_name.clone(),
                    tls_mode: entry.tls_mode,
                    conn: conn.clone(),
                });
            }
        }
        None
    }
}
