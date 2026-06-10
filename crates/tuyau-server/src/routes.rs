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

/// All tunnels currently serving one hostname. With `last-write-wins` there is
/// ever only one; with `round-robin` there may be several (active-active), and
/// `cursor` spreads public connections across them.
#[derive(Debug)]
struct HostRoutes {
    client_name: String,
    tls_mode: TlsMode,
    balance: Balance,
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
                balance,
                conns: Vec::new(),
                cursor: AtomicUsize::new(0),
            });
            // Refresh metadata to the latest config view for this client.
            entry.client_name = client_name.to_string();
            entry.tls_mode = tls_mode;
            entry.balance = balance;

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
