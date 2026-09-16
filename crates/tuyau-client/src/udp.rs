//! UDP forwarding on the tunnel client: deliver datagrams to a local UDP
//! service and send its replies back.
//!
//! The server demultiplexes public UDP traffic into sessions and tags every
//! datagram with `(session id, route)`. This side turns each session into
//! **its own local socket**, connected to the route's `local_addr`.
//!
//! One socket per session is the whole point, not an implementation detail. It
//! is what gives the local service a distinct source address per public peer,
//! so a stateful protocol can tell peers apart — and, crucially, what makes
//! roaming work without tuyau having to authenticate anything. When a public
//! peer's address changes (NAT rebinding, wifi → 4G), the server opens a *new*
//! session, so the local service sees a new source address, exactly as it would
//! if the peer had roamed with no proxy in the path. WireGuard authenticates
//! the packet, moves the peer's endpoint to the new socket, and replies flow
//! back down the new session. A spoofed packet gets its own session too — and
//! its own rejection from the service, which holds the keys tuyau does not.
//!
//! Sessions here are soft state: they expire on idle and are rebuilt from the
//! next datagram, because every datagram carries its route.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use tuyau_protocol::UdpDatagram;

/// Receive buffer for a reply from the local service. 64 KiB is the largest
/// legal UDP payload, so nothing the service sends is truncated here (the
/// tunnel MTU check is what bounds what can actually pass).
const RECV_BUF: usize = 64 * 1024;

/// Drop a session after this long with no datagram in either direction. The
/// server keeps the authoritative timeout; this one only has to be long enough
/// not to churn sockets under a live session, since a reaped session is rebuilt
/// by the next datagram.
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// How often to sweep for idle sessions.
const REAP_INTERVAL: Duration = Duration::from_secs(15);

/// Cap on concurrent UDP sessions (and therefore local sockets / file
/// descriptors) this client holds. The server enforces the configurable,
/// operator-facing cap; this is a backstop so a misbehaving or compromised
/// server cannot make the client exhaust its descriptors.
const MAX_SESSIONS: usize = 4096;

/// One forwarded UDP session: the local socket standing in for a public peer.
struct Session {
    socket: Arc<UdpSocket>,
    last_seen_ms: AtomicU64,
}

/// Forwards UDP datagrams between the tunnel and local services for one
/// connection.
pub(crate) struct UdpForwarder {
    conn: quinn::Connection,
    /// Route name → local `host:port`, from `[[udp_ingress]]`.
    routes: Arc<HashMap<String, String>>,
    // parking_lot: a panic while a guard is held must not poison the map and
    // wedge every UDP session on the tunnel.
    sessions: Mutex<HashMap<u64, Arc<Session>>>,
    epoch: Instant,
}

impl UdpForwarder {
    pub(crate) fn new(conn: quinn::Connection, routes: Arc<HashMap<String, String>>) -> Arc<Self> {
        Arc::new(Self {
            conn,
            routes,
            sessions: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
        })
    }

    /// Read datagrams off the tunnel and forward them until it closes.
    ///
    /// Runs even with no `[[udp_ingress]]` configured: draining and dropping is
    /// cheap, and it keeps "the server sent UDP we can't route" a logged fact
    /// rather than silent back-pressure on the tunnel's datagram queue.
    pub(crate) async fn run(self: Arc<Self>) {
        let reaper = {
            let this = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(REAP_INTERVAL);
                loop {
                    tick.tick().await;
                    this.reap();
                }
            })
        };

        loop {
            let bytes = match self.conn.read_datagram().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = %e, "udp datagram loop ending");
                    break;
                }
            };

            let dg = match UdpDatagram::decode(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(error = %e, "malformed udp datagram from server, dropping");
                    continue;
                }
            };

            let session = match self.session_for(dg.session_id, dg.route).await {
                Some(s) => s,
                None => continue,
            };
            session
                .last_seen_ms
                .store(self.elapsed_ms(), Ordering::Relaxed);

            if let Err(e) = session.socket.send(dg.payload).await {
                tracing::debug!(session = dg.session_id, error = %e, "local udp send failed");
            }
        }

        reaper.abort();
        self.sessions.lock().clear();
    }

    /// Existing session, or a new one bound for `route`. `None` when the route
    /// is unknown, the local socket won't bind, or the session cap is reached.
    async fn session_for(&self, id: u64, route: &str) -> Option<Arc<Session>> {
        if let Some(s) = self.sessions.lock().get(&id) {
            return Some(s.clone());
        }

        let Some(local_addr) = self.routes.get(route) else {
            tracing::warn!(route = %route, "no udp_ingress rule for route, dropping datagram");
            return None;
        };

        // Check the cap before doing any work; past it, drop rather than grow.
        if self.sessions.lock().len() >= MAX_SESSIONS {
            tracing::warn!(
                route = %route,
                max = MAX_SESSIONS,
                "udp session cap reached, dropping datagram"
            );
            return None;
        }

        let socket = match bind_connected(local_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::warn!(
                    route = %route,
                    local_addr = %local_addr,
                    error = %e,
                    "failed to open a local udp socket, dropping datagram"
                );
                return None;
            }
        };

        let session = Arc::new(Session {
            socket: socket.clone(),
            last_seen_ms: AtomicU64::new(self.elapsed_ms()),
        });

        // Re-check under the lock: two datagrams of a new session can race here
        // (they are unordered by construction), and the loser's socket must be
        // dropped rather than leak or replace the winner's.
        {
            let mut guard = self.sessions.lock();
            if let Some(existing) = guard.get(&id) {
                return Some(existing.clone());
            }
            guard.insert(id, session.clone());
        }

        tracing::debug!(session = id, route = %route, local_addr = %local_addr, "new udp session");
        self.spawn_reply_pump(id, route.to_string(), socket);
        Some(session)
    }

    /// Read replies from the local service and send them back over the tunnel,
    /// tagged with the session they belong to. Ends when the session is reaped
    /// (the socket is dropped) or the tunnel closes.
    fn spawn_reply_pump(&self, id: u64, route: String, socket: Arc<UdpSocket>) {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                let len = match socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(session = id, error = %e, "local udp recv failed");
                        return;
                    }
                };

                // Oversized packets are dropped, not fragmented: reassembly
                // state is unbounded per-peer memory, and a lost fragment costs
                // the whole packet anyway. Lower the tunneled protocol's MTU.
                let Some(max) = conn.max_datagram_size() else {
                    tracing::warn!(session = id, "tunnel does not support QUIC datagrams");
                    return;
                };
                let budget = UdpDatagram::max_payload(max, &route);
                if len > budget {
                    tracing::warn!(
                        session = id,
                        route = %route,
                        len,
                        max_payload = budget,
                        "udp reply does not fit the tunnel MTU, dropping — lower the local service's MTU"
                    );
                    continue;
                }

                let dg = UdpDatagram {
                    session_id: id,
                    route: &route,
                    payload: &buf[..len],
                };
                let encoded = match dg.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error = %e, route = %route, "udp datagram encode failed");
                        continue;
                    }
                };
                if let Err(e) = conn.send_datagram(encoded.into()) {
                    tracing::debug!(session = id, error = %e, "udp datagram send failed");
                    if conn.close_reason().is_some() {
                        return;
                    }
                }
            }
        });
    }

    /// Drop sessions idle past [`IDLE_TIMEOUT`]. Dropping the session drops its
    /// socket, which ends the reply pump on its next read.
    fn reap(&self) {
        let now = self.elapsed_ms();
        let deadline = IDLE_TIMEOUT.as_millis() as u64;
        let mut guard = self.sessions.lock();
        let before = guard.len();
        guard.retain(|_, s| now.saturating_sub(s.last_seen_ms.load(Ordering::Relaxed)) <= deadline);
        let reaped = before - guard.len();
        if reaped > 0 {
            tracing::debug!(sessions = reaped, "reaped idle udp sessions");
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }
}

/// Bind an ephemeral socket in the target's address family and connect it, so
/// sends need no address and the kernel drops anything not from the service.
async fn bind_connected(target: &str) -> std::io::Result<UdpSocket> {
    // Resolve first: the bind family has to match the target's.
    let addr = tokio::net::lookup_host(target)
        .await?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("no address resolved for '{target}'")))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_connected_matches_the_target_family() {
        let v4 = bind_connected("127.0.0.1:9").await.unwrap();
        assert!(v4.local_addr().unwrap().is_ipv4());

        // IPv6 may be unavailable in a container; only assert when it binds.
        if let Ok(v6) = bind_connected("[::1]:9").await {
            assert!(v6.local_addr().unwrap().is_ipv6());
        }
    }

    #[tokio::test]
    async fn bind_connected_rejects_an_unresolvable_target() {
        assert!(bind_connected("no-such-host.invalid:9").await.is_err());
    }
}
