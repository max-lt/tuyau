use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::config::TlsMode;

#[derive(Debug, Clone)]
pub struct RouteEntry {
    // `client_name` and `tls_mode` are populated for M5a but only consumed
    // starting M5b (public listener / dispatch). Keep them readable now so the
    // table is feature-complete at write time.
    #[allow(dead_code)]
    pub client_name: String,
    #[allow(dead_code)]
    pub tls_mode: TlsMode,
    pub conn: quinn::Connection,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    inner: Arc<RwLock<HashMap<String, RouteEntry>>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install routes for a freshly authenticated connection. If any of the
    /// requested hosts is currently held by a different `quinn::Connection`
    /// (necessarily owned by a previous session of the same matched client,
    /// since `host` is unique by config validation), that connection is
    /// returned so the caller can close it — last-write-wins on reconnect.
    pub fn install(
        &self,
        hosts: Vec<(String, TlsMode)>,
        client_name: &str,
        conn: &quinn::Connection,
    ) -> Option<quinn::Connection> {
        if hosts.is_empty() {
            return None;
        }

        let mut guard = self.inner.write().expect("routes lock poisoned");
        let new_id = conn.stable_id();
        let mut kicked: Option<quinn::Connection> = None;

        for (host, _) in &hosts {
            if let Some(existing) = guard.get(host)
                && existing.conn.stable_id() != new_id
            {
                kicked = Some(existing.conn.clone());
            }
        }

        for (host, tls_mode) in hosts {
            guard.insert(
                host,
                RouteEntry {
                    client_name: client_name.to_string(),
                    tls_mode,
                    conn: conn.clone(),
                },
            );
        }

        kicked
    }

    /// Remove every entry whose connection matches `stable_id`. Called when
    /// the owning connection closes (peer-initiated, timeout, or shutdown).
    pub fn remove_conn(&self, stable_id: usize) {
        let mut guard = self.inner.write().expect("routes lock poisoned");
        guard.retain(|_, entry| entry.conn.stable_id() != stable_id);
    }

    /// Sorted snapshot of currently active hostnames.
    pub fn active_hostnames(&self) -> Vec<String> {
        let guard = self.inner.read().expect("routes lock poisoned");
        let mut hosts: Vec<String> = guard.keys().cloned().collect();
        hosts.sort();
        hosts
    }
}
