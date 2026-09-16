//! Public UDP listener: per-port routing, session demultiplexing, and the
//! return path.
//!
//! UDP gives the proxy none of what TCP does. There is no connection to accept,
//! no SNI to route on, and the kernel hands every peer's traffic to the same
//! socket — so this module has to invent the parts the public listener gets for
//! free on TCP:
//!
//! - **Routing** is per-port: one `[[udp]]` entry, one bound socket, one route.
//!   No payload inspection, so any protocol works, and nothing shares a port.
//! - **Sessions** are a fiction maintained here: `(route, public peer addr)` →
//!   a session id, forwarded either over the owning client's tunnel (as a QUIC
//!   DATAGRAM) or to a local UDP service. They die on idle; nothing else ends
//!   them.
//! - **The return path is immutable.** A session's reply address is the address
//!   that opened it and never changes. That is the whole answer to roaming and
//!   to spoofing, and it is worth being explicit about why:
//!
//! ## Roaming without trusting anybody
//!
//! A client's source address changes constantly — NAT rebinding, wifi → 4G.
//! WireGuard and QUIC survive that natively because a mid-session packet
//! carries an identifier (WG receiver index, QUIC connection id) that the
//! *endpoint* can authenticate. A proxy holds no keys, so it cannot: matching
//! on those identifiers and repointing the session would let anyone who ever
//! observed a packet redirect the session to themselves, kill it, or use tuyau
//! as a reflector.
//!
//! So tuyau does not try. A datagram from an unknown address is simply a new
//! session, with its own id and its own return address. The tunnel client gives
//! each session its own local socket, so the far-side service sees the roamed
//! peer as a new source address — exactly what it sees when a peer roams
//! without a proxy in the path — and its own cryptography decides whether to
//! accept it. WireGuard authenticates the handshake or data packet and moves
//! the peer's endpoint; replies then flow back down the new session. The
//! session that roamed away idles out.
//!
//! A spoofed packet from a third address takes the same path and gets the same
//! treatment: a fresh session, a fresh local socket, and a far side that
//! rejects the unauthenticated packet. It cannot touch the existing session,
//! because no packet from anywhere can change a session's return address.
//!
//! ## Not being an amplifier
//!
//! Source addresses are forgeable, so anything sent toward an unvalidated peer
//! is potentially sent at a victim. Until a session shows evidence of a
//! completed round trip (the peer kept sending *after* we replied), the bytes
//! sent toward it are capped at the route's `amplification_factor`× the bytes
//! received from it — by default 3, the same rule QUIC applies to unvalidated
//! paths. Session tables are bounded globally and per source IP, so a flood of
//! forged sources costs memory that is capped in advance rather than memory
//! that grows.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use tuyau_protocol::UdpDatagram;

use crate::config::UdpEntry;
use crate::error::ServerError;
use crate::routes::RoutingTable;

/// Receive buffer for one datagram. 64 KiB covers the largest legal UDP
/// payload, so nothing a peer sends is ever truncated by us (the tunnel's MTU
/// check further down is what actually bounds what can pass).
const RECV_BUF: usize = 64 * 1024;

/// How often the reaper sweeps for expired sessions.
const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Idle timeout for a session that has never heard back from the backend. Kept
/// short so a flood of forged source addresses drains quickly instead of
/// sitting on the table for the full configured timeout.
const UNANSWERED_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Pause after a failed `recv_from` before retrying, so a persistent socket
/// error can't spin the receive loop at 100% CPU. Mirrors the TCP accept-loop
/// backoff in `public.rs`.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Per-IP session cap, derived from the route's global cap. One source IP must
/// not be able to fill the whole table and starve every other peer. The floor
/// keeps it usable when the global cap is tiny (tests).
fn max_sessions_per_ip(global: usize) -> usize {
    (global / 8).max(16)
}

/// Where a session's datagrams go once they leave the public socket.
enum Sink {
    /// Over a client tunnel as QUIC datagrams. The return path is the tunnel's
    /// datagram pump ([`spawn_tunnel_pump`]).
    Tunnel {
        conn: quinn::Connection,
        /// Connection identity checked on the return path, so one tunnel can
        /// never write into another tunnel's session.
        conn_id: usize,
    },
    /// To a local UDP service, from a socket dedicated to this session (so the
    /// service sees one source address per public peer, and replies come back
    /// unambiguously). The return path is this session's own reader task.
    Local { socket: Arc<UdpSocket> },
}

/// One UDP session: a public peer's traffic on one route.
///
/// Everything that identifies where replies go — `peer`, `listener`, `route` —
/// is immutable for the session's whole life. Only counters and timestamps
/// move, and they are atomics so the hot path never takes a lock to update
/// them.
struct Session {
    id: u64,
    route: Arc<str>,
    /// Public socket replies are written to.
    listener: Arc<UdpSocket>,
    /// The one address this session will ever reply to.
    peer: SocketAddr,
    sink: Sink,
    /// Millis since the router's epoch, for idle expiry.
    last_seen_ms: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    /// The backend has answered at least once.
    answered: AtomicBool,
    /// Round-trip evidence: the peer sent again after we replied, so it is
    /// plausibly receiving what we send. Lifts the amplification cap.
    validated: AtomicBool,
    /// Bytes sendable per byte received while unvalidated (route config).
    amplification_factor: u64,
    /// Stops this session's reader task (local sink only).
    cancel: CancellationToken,
    /// Held for the session's lifetime; releases the per-IP slot on drop.
    _ip_permit: IpPermit,
}

impl Session {
    fn touch(&self, epoch: Instant) {
        self.last_seen_ms
            .store(elapsed_ms(epoch), Ordering::Relaxed);
    }

    /// Account a datagram received from the public peer. A peer that keeps
    /// sending after we have replied is treated as address-validated.
    fn note_rx(&self, n: usize, epoch: Instant) {
        self.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        if self.answered.load(Ordering::Relaxed) {
            self.validated.store(true, Ordering::Relaxed);
        }
        self.touch(epoch);
    }

    /// Whether `n` bytes may be sent toward the peer right now. Before the
    /// session is validated the peer's address is unproven, so the reply volume
    /// stays within `amplification_factor`× what it sent us.
    fn may_send(&self, n: usize) -> bool {
        if self.validated.load(Ordering::Relaxed) {
            return true;
        }
        let budget = self
            .rx_bytes
            .load(Ordering::Relaxed)
            .saturating_mul(self.amplification_factor);
        self.tx_bytes
            .load(Ordering::Relaxed)
            .saturating_add(n as u64)
            <= budget
    }

    fn note_tx(&self, n: usize, epoch: Instant) {
        self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        self.answered.store(true, Ordering::Relaxed);
        self.touch(epoch);
    }

    /// Send one datagram back to the public peer, subject to the amplification
    /// budget. Returns whether it was sent.
    async fn reply(&self, payload: &[u8], epoch: Instant) -> bool {
        if !self.may_send(payload.len()) {
            tracing::debug!(
                session = self.id,
                route = %self.route,
                peer = %self.peer,
                len = payload.len(),
                factor = self.amplification_factor,
                "reply exceeds the anti-amplification budget for an unvalidated peer, dropping \
                 (raise the route's amplification_factor if the protocol needs it)"
            );
            return false;
        }
        match self.listener.send_to(payload, self.peer).await {
            Ok(n) => {
                self.note_tx(n, epoch);
                true
            }
            Err(e) => {
                tracing::debug!(session = self.id, error = %e, "udp reply send failed");
                false
            }
        }
    }

    fn idle_deadline(&self, configured: Duration) -> Duration {
        if self.answered.load(Ordering::Relaxed) {
            configured
        } else {
            // Nothing has come back for this peer yet: it may well be a forged
            // source address. Expire it early instead of holding a slot.
            UNANSWERED_IDLE_TIMEOUT.min(configured)
        }
    }
}

/// Counts live sessions per source IP so one address can't take the whole
/// table. Same shape as the public listener's per-IP connection limiter.
#[derive(Clone)]
struct PerIpLimiter {
    max_per_ip: usize,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

struct IpPermit {
    ip: IpAddr,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl PerIpLimiter {
    fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> Option<IpPermit> {
        let mut counts = self.counts.lock();
        let c = counts.entry(ip).or_insert(0);
        if *c >= self.max_per_ip {
            return None;
        }
        *c += 1;
        Some(IpPermit {
            ip,
            counts: self.counts.clone(),
        })
    }
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(c) = counts.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Session tables. Two views of the same sessions: the forward path looks them
/// up by peer address, the return path by session id. Both live under one lock
/// so they can never disagree about what exists.
///
/// parking_lot, like the routing table: a panic while a guard is held must not
/// poison the lock and take every UDP route down with it.
#[derive(Default)]
struct Tables {
    by_peer: HashMap<(Arc<str>, SocketAddr), Arc<Session>>,
    by_id: HashMap<u64, Arc<Session>>,
    /// Live session count per route, maintained alongside the maps. The cap is
    /// checked for every datagram from an unknown peer, so it must not be a
    /// scan: under a flood of forged source addresses that would turn the cap
    /// itself into the CPU-exhaustion vector it exists to prevent.
    per_route: HashMap<Arc<str>, usize>,
}

impl Tables {
    fn insert(&mut self, session: Arc<Session>) {
        let route = session.route.clone();
        if self
            .by_peer
            .insert((route.clone(), session.peer), session.clone())
            .is_none()
        {
            *self.per_route.entry(route).or_insert(0) += 1;
        }
        self.by_id.insert(session.id, session);
    }

    /// Drop one session from every index. Cancelling its task is the caller's
    /// job, so a batch removal can hold the lock once.
    fn remove(&mut self, session: &Session) {
        if self
            .by_peer
            .remove(&(session.route.clone(), session.peer))
            .is_some()
            && let Some(c) = self.per_route.get_mut(&session.route)
        {
            *c -= 1;
            if *c == 0 {
                self.per_route.remove(&session.route);
            }
        }
        self.by_id.remove(&session.id);
    }
}

/// Shared session state across every UDP route on this server. One instance is
/// held by the listeners (forward path) and by each tunnel's datagram pump
/// (return path).
pub(crate) struct UdpRouter {
    tables: Mutex<Tables>,
    next_id: AtomicU64,
    /// Reference point for the millisecond timestamps in [`Session`].
    epoch: Instant,
}

impl UdpRouter {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            tables: Mutex::new(Tables::default()),
            // Start above zero so a session id is never confusable with an
            // uninitialised field on the wire.
            next_id: AtomicU64::new(1),
            epoch: Instant::now(),
        })
    }

    fn get(&self, route: &Arc<str>, peer: SocketAddr) -> Option<Arc<Session>> {
        self.tables
            .lock()
            .by_peer
            .get(&(route.clone(), peer))
            .cloned()
    }

    fn by_id(&self, id: u64) -> Option<Arc<Session>> {
        self.tables.lock().by_id.get(&id).cloned()
    }

    fn insert(&self, session: Arc<Session>) {
        self.tables.lock().insert(session);
    }

    fn remove(&self, session: &Session) {
        self.tables.lock().remove(session);
        session.cancel.cancel();
    }

    /// Number of live sessions on `route` (used for the per-route cap).
    fn count_for_route(&self, route: &str) -> usize {
        self.tables
            .lock()
            .per_route
            .get(route)
            .copied()
            .unwrap_or(0)
    }

    /// Drop every session matching `doomed`, in one pass under one lock.
    fn remove_matching(&self, doomed: impl Fn(&Session) -> bool) -> usize {
        let mut t = self.tables.lock();
        let hits: Vec<Arc<Session>> = t.by_id.values().filter(|s| doomed(s)).cloned().collect();
        for s in &hits {
            t.remove(s);
        }
        drop(t);
        for s in &hits {
            s.cancel.cancel();
        }
        hits.len()
    }

    /// Drop every session that forwards over `conn_id`. Called when a tunnel
    /// goes away: its sessions can never be served again, and leaving them to
    /// idle out would hold slots a reconnecting client needs.
    fn drop_sessions_for_conn(&self, conn_id: usize) -> usize {
        self.remove_matching(|s| matches!(s.sink, Sink::Tunnel { conn_id: c, .. } if c == conn_id))
    }

    /// Drop `route`'s sessions that are idle past their deadline. Scoped to one
    /// route because `idle` is that route's configured timeout — applying it to
    /// another route's sessions would reap them on the wrong schedule.
    fn reap(&self, route: &str, idle: Duration) -> usize {
        let now = elapsed_ms(self.epoch);
        self.remove_matching(|s| {
            s.route.as_ref() == route && {
                let deadline = s.idle_deadline(idle).as_millis() as u64;
                now.saturating_sub(s.last_seen_ms.load(Ordering::Relaxed)) > deadline
            }
        })
    }
}

fn elapsed_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

pub(crate) struct UdpListenerHandle {
    pub name: String,
    pub local_addr: SocketAddr,
    pub join: JoinHandle<()>,
}

/// Bind every configured `[[udp]]` route and start its receive loop.
pub(crate) async fn start_all(
    entries: &[UdpEntry],
    routes: RoutingTable,
    router: Arc<UdpRouter>,
    cancel: CancellationToken,
) -> Result<Vec<UdpListenerHandle>, ServerError> {
    let mut handles = Vec::with_capacity(entries.len());
    for entry in entries {
        handles.push(start_one(entry, routes.clone(), router.clone(), cancel.clone()).await?);
    }
    Ok(handles)
}

async fn start_one(
    entry: &UdpEntry,
    routes: RoutingTable,
    router: Arc<UdpRouter>,
    cancel: CancellationToken,
) -> Result<UdpListenerHandle, ServerError> {
    let socket = Arc::new(UdpSocket::bind(entry.listen_addr).await.map_err(|e| {
        tracing::error!(error = %e, udp_route = %entry.name, listen_addr = %entry.listen_addr, "udp listener bind failed");
        e
    })?);
    let local_addr = socket.local_addr()?;
    let name = entry.name.clone();

    let cfg = RouteConfig {
        name: Arc::from(entry.name.as_str()),
        local_addr: entry.local_addr,
        idle_timeout: entry.idle_timeout(),
        max_sessions: entry.max_sessions(),
        amplification_factor: entry.amplification_factor(),
    };
    let per_ip = PerIpLimiter::new(max_sessions_per_ip(cfg.max_sessions));

    tracing::info!(
        udp_route = %entry.name,
        listen_addr = %local_addr,
        target = %match entry.local_addr {
            Some(a) => format!("local:{a}"),
            None => format!("tunnel:{}", entry.client.as_deref().unwrap_or("?")),
        },
        idle_timeout_secs = cfg.idle_timeout.as_secs(),
        max_sessions = cfg.max_sessions,
        amplification_factor = cfg.amplification_factor,
        "public UDP listener active"
    );

    let reaper = {
        let router = router.clone();
        let idle = cfg.idle_timeout;
        let cancel = cancel.clone();
        let name = cfg.name.clone();
        async move {
            let mut tick = tokio::time::interval(REAP_INTERVAL);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tick.tick() => {
                        let n = router.reap(&name, idle);
                        if n > 0 {
                            tracing::debug!(udp_route = %name, sessions = n, "reaped idle udp sessions");
                        }
                    }
                }
            }
        }
    };

    let join = tokio::spawn(async move {
        tokio::join!(
            recv_loop(socket, cfg, routes, router, per_ip, cancel),
            reaper
        );
    });

    Ok(UdpListenerHandle {
        name,
        local_addr,
        join,
    })
}

/// The per-route knobs the receive loop needs, resolved once at bind time.
struct RouteConfig {
    name: Arc<str>,
    /// `Some` for a static local upstream, `None` for a tunnel route.
    local_addr: Option<SocketAddr>,
    idle_timeout: Duration,
    max_sessions: usize,
    amplification_factor: u64,
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    cfg: RouteConfig,
    routes: RoutingTable,
    router: Arc<UdpRouter>,
    per_ip: PerIpLimiter,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, peer) = tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!(udp_route = %cfg.name, "udp receive loop cancelled");
                return;
            }
            res = socket.recv_from(&mut buf) => match res {
                Ok(x) => x,
                Err(e) => {
                    // Back off so a persistent error can't spin at 100% CPU.
                    tracing::warn!(udp_route = %cfg.name, error = %e, "udp recv failed; backing off");
                    tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                    continue;
                }
            },
        };

        let session = match router.get(&cfg.name, peer) {
            Some(s) => s,
            None => {
                match open_session(&socket, &cfg, &routes, &router, &per_ip, peer, &cancel).await {
                    Some(s) => s,
                    // No route, no capacity, or the local socket wouldn't bind:
                    // drop the datagram. UDP has no error to send back, and
                    // inventing one would make this an amplifier.
                    None => continue,
                }
            }
        };

        session.note_rx(len, router.epoch);
        forward(&session, &buf[..len], &router).await;
    }
}

/// Create a session for a peer we haven't seen on this route, if the route is
/// live and there is room for it.
async fn open_session(
    listener: &Arc<UdpSocket>,
    cfg: &RouteConfig,
    routes: &RoutingTable,
    router: &Arc<UdpRouter>,
    per_ip: &PerIpLimiter,
    peer: SocketAddr,
    cancel: &CancellationToken,
) -> Option<Arc<Session>> {
    if router.count_for_route(&cfg.name) >= cfg.max_sessions {
        tracing::debug!(udp_route = %cfg.name, peer = %peer, "udp session cap reached, dropping");
        return None;
    }
    let ip_permit = match per_ip.try_acquire(peer.ip()) {
        Some(p) => p,
        None => {
            tracing::debug!(udp_route = %cfg.name, peer = %peer, "per-IP udp session cap reached, dropping");
            return None;
        }
    };

    let session_cancel = cancel.child_token();
    let sink = match cfg.local_addr {
        Some(addr) => {
            // One socket per session, connected to the local service: the
            // service sees a distinct source per public peer, which is what
            // lets its own protocol tell roamed peers apart.
            let sock = match bind_local_socket(addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::warn!(udp_route = %cfg.name, peer = %peer, local_addr = %addr, error = %e, "local udp socket setup failed");
                    return None;
                }
            };
            Sink::Local { socket: sock }
        }
        None => {
            let (client_name, conn) = routes.lookup_udp(&cfg.name)?;
            tracing::debug!(
                udp_route = %cfg.name,
                peer = %peer,
                client = %client_name,
                "new udp session over tunnel"
            );
            let conn_id = conn.stable_id();
            Sink::Tunnel { conn, conn_id }
        }
    };

    let session = Arc::new(Session {
        id: router.next_id.fetch_add(1, Ordering::Relaxed),
        route: cfg.name.clone(),
        listener: listener.clone(),
        peer,
        sink,
        last_seen_ms: AtomicU64::new(elapsed_ms(router.epoch)),
        rx_bytes: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        answered: AtomicBool::new(false),
        validated: AtomicBool::new(false),
        amplification_factor: cfg.amplification_factor,
        cancel: session_cancel,
        _ip_permit: ip_permit,
    });
    router.insert(session.clone());

    if let Sink::Local { socket } = &session.sink {
        spawn_local_reader(session.clone(), socket.clone(), router.clone());
    }

    Some(session)
}

/// Bind an ephemeral socket in the target's address family and connect it, so
/// `send`/`recv` need no address and the kernel filters out anything not from
/// the local service.
async fn bind_local_socket(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("[::]:0 parses")
    } else {
        "0.0.0.0:0".parse().expect("0.0.0.0:0 parses")
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(target).await?;
    Ok(sock)
}

/// Forward one datagram from the public peer toward the session's backend.
async fn forward(session: &Arc<Session>, payload: &[u8], router: &Arc<UdpRouter>) {
    match &session.sink {
        Sink::Local { socket } => {
            if let Err(e) = socket.send(payload).await {
                tracing::debug!(session = session.id, error = %e, "local udp forward failed");
            }
        }
        Sink::Tunnel { conn, .. } => {
            send_over_tunnel(conn, session.id, &session.route, payload);
            // A tunnel whose peer has gone away leaves its sessions unusable;
            // let the pump's cleanup handle it rather than guessing here.
            if conn.close_reason().is_some() {
                router.remove(session);
            }
        }
    }
}

/// Encapsulate and send one datagram over a tunnel.
///
/// Oversized packets are **dropped**, not fragmented: a fragment lost on an
/// unreliable datagram costs the whole packet anyway, and reassembly state is
/// exactly the kind of unbounded per-peer memory this module avoids. Operators
/// lower the tunneled protocol's MTU instead (see the README).
fn send_over_tunnel(conn: &quinn::Connection, session_id: u64, route: &str, payload: &[u8]) {
    let Some(max) = conn.max_datagram_size() else {
        tracing::warn!(
            session = session_id,
            route = %route,
            "tunnel peer does not support QUIC datagrams; udp forwarding unavailable"
        );
        return;
    };
    let budget = UdpDatagram::max_payload(max, route);
    if payload.len() > budget {
        tracing::warn!(
            session = session_id,
            route = %route,
            len = payload.len(),
            max_payload = budget,
            "udp packet does not fit the tunnel MTU, dropping — lower the tunneled protocol's MTU"
        );
        return;
    }

    let dg = UdpDatagram {
        session_id,
        route,
        payload,
    };
    let encoded = match dg.encode() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, route = %route, "udp datagram encode failed");
            return;
        }
    };
    if let Err(e) = conn.send_datagram(encoded.into()) {
        tracing::debug!(session = session_id, error = %e, "udp datagram send failed");
    }
}

/// Pump replies from a local service back to its public peer. One task per
/// session; it ends when the session is reaped or the server shuts down.
fn spawn_local_reader(session: Arc<Session>, socket: Arc<UdpSocket>, router: Arc<UdpRouter>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let len = tokio::select! {
                _ = session.cancel.cancelled() => return,
                res = socket.recv(&mut buf) => match res {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(session = session.id, error = %e, "local udp recv failed");
                        router.remove(&session);
                        return;
                    }
                },
            };
            session.reply(&buf[..len], router.epoch).await;
        }
    });
}

/// Pump a tunnel's incoming QUIC datagrams back out to their public peers.
///
/// One task per authenticated tunnel, started only when the tunnel serves at
/// least one UDP route. Every datagram is checked against the session table
/// before a byte leaves the public socket: the session must exist, it must
/// belong to *this* tunnel, and it must be on the route the datagram claims.
/// The peer address it goes to comes from the session, never from the wire.
pub(crate) fn spawn_tunnel_pump(
    conn: quinn::Connection,
    router: Arc<UdpRouter>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let conn_id = conn.stable_id();
        loop {
            let bytes = tokio::select! {
                _ = cancel.cancelled() => break,
                res = conn.read_datagram() => match res {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::debug!(error = %e, "tunnel datagram pump ending");
                        break;
                    }
                },
            };

            let dg = match UdpDatagram::decode(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    // Malformed input from a peer is expected traffic, not an
                    // error worth tearing the tunnel down for.
                    tracing::debug!(error = %e, "malformed udp datagram from tunnel, dropping");
                    continue;
                }
            };

            let Some(session) = router.by_id(dg.session_id) else {
                // Expired or never existed — e.g. a reply that raced the idle
                // reaper. Nothing to do; there is no address to send it to.
                tracing::trace!(session = dg.session_id, "udp datagram for unknown session");
                continue;
            };
            // A session id is only meaningful within the tunnel that owns it.
            // Without this check a client could name another client's session
            // and write at its public peer.
            if !matches!(session.sink, Sink::Tunnel { conn_id: c, .. } if c == conn_id) {
                tracing::warn!(
                    session = dg.session_id,
                    "udp datagram for a session owned by another tunnel, dropping"
                );
                continue;
            }
            if session.route.as_ref() != dg.route {
                tracing::debug!(
                    session = dg.session_id,
                    claimed = %dg.route,
                    actual = %session.route,
                    "udp datagram route mismatch, dropping"
                );
                continue;
            }

            session.reply(dg.payload, router.epoch).await;
        }

        let dropped = router.drop_sessions_for_conn(conn_id);
        if dropped > 0 {
            tracing::debug!(
                sessions = dropped,
                "dropped udp sessions of a closed tunnel"
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_session(peer: SocketAddr, listener: Arc<UdpSocket>, epoch: Instant) -> Session {
        session_on("wg", 1, peer, listener, epoch)
    }

    fn session_on(
        route: &str,
        id: u64,
        peer: SocketAddr,
        listener: Arc<UdpSocket>,
        epoch: Instant,
    ) -> Session {
        Session {
            id,
            route: Arc::from(route),
            listener,
            peer,
            sink: Sink::Local {
                socket: Arc::clone(&listener_placeholder()),
            },
            last_seen_ms: AtomicU64::new(elapsed_ms(epoch)),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            answered: AtomicBool::new(false),
            validated: AtomicBool::new(false),
            amplification_factor: 3,
            cancel: CancellationToken::new(),
            _ip_permit: PerIpLimiter::new(1)
                .try_acquire(peer.ip())
                .expect("fresh limiter has room"),
        }
    }

    /// A bound socket to fill the `Sink::Local` field in unit tests; never sent on.
    fn listener_placeholder() -> Arc<UdpSocket> {
        use std::sync::OnceLock;
        static S: OnceLock<Arc<UdpSocket>> = OnceLock::new();
        S.get_or_init(|| {
            let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            std_sock.set_nonblocking(true).unwrap();
            Arc::new(UdpSocket::from_std(std_sock).unwrap())
        })
        .clone()
    }

    #[tokio::test]
    async fn unvalidated_sessions_cannot_amplify() {
        let epoch = Instant::now();
        let peer: SocketAddr = (Ipv4Addr::LOCALHOST, 1234).into();
        let s = test_session(peer, listener_placeholder(), epoch);

        // Nothing received yet: nothing may be sent. A proxy that answered here
        // would reflect traffic at whatever address a spoofer named.
        assert!(!s.may_send(1));

        // With the default factor of 3: 100 bytes in buys 300 bytes out, and
        // not one more.
        s.note_rx(100, epoch);
        assert!(s.may_send(300));
        assert!(!s.may_send(301));

        s.note_tx(300, epoch);
        assert!(!s.may_send(1), "budget is spent");

        // The peer keeps sending after our reply — round-trip evidence, so the
        // cap lifts and an asymmetric (download-shaped) flow can proceed.
        s.note_rx(1, epoch);
        assert!(s.validated.load(Ordering::Relaxed));
        assert!(s.may_send(1_000_000));
    }

    #[tokio::test]
    async fn unanswered_sessions_expire_early() {
        let epoch = Instant::now();
        let peer: SocketAddr = (Ipv4Addr::LOCALHOST, 1234).into();
        let s = test_session(peer, listener_placeholder(), epoch);
        let configured = Duration::from_secs(120);

        // A peer the backend has never answered may well be a forged source:
        // it gets the short deadline, not the configured one.
        assert_eq!(s.idle_deadline(configured), UNANSWERED_IDLE_TIMEOUT);
        s.note_tx(10, epoch);
        assert_eq!(s.idle_deadline(configured), configured);

        // A configured timeout below the floor still wins — never extend a
        // session past what the operator asked for.
        let short = Duration::from_secs(5);
        assert_eq!(
            test_session(peer, listener_placeholder(), epoch).idle_deadline(short),
            short
        );
    }

    #[test]
    fn per_ip_limiter_caps_and_releases() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let lim = PerIpLimiter::new(2);

        let a = lim.try_acquire(ip).expect("1st under cap");
        let b = lim.try_acquire(ip).expect("2nd under cap");
        assert!(lim.try_acquire(ip).is_none(), "3rd from same IP is capped");
        let c = lim.try_acquire(other).expect("other IP independent");

        drop(b);
        let d = lim.try_acquire(ip).expect("slot freed → acquire again");

        drop(a);
        drop(d);
        drop(c);
        assert!(lim.counts.lock().is_empty(), "map must not leak IP entries");
    }

    #[test]
    fn per_ip_cap_derives_from_global_with_floor() {
        assert_eq!(max_sessions_per_ip(4096), 512);
        assert_eq!(max_sessions_per_ip(1), 16);
    }

    #[tokio::test]
    async fn session_return_address_is_immutable() {
        // The anti-hijack property, stated as a table invariant: a session is
        // keyed on its peer, so a datagram from a different address can only
        // ever produce a *different* session — there is no code path that
        // repoints an existing one.
        let router = UdpRouter::new();
        let route: Arc<str> = Arc::from("wg");
        let listener = listener_placeholder();
        let victim: SocketAddr = (Ipv4Addr::LOCALHOST, 1111).into();
        let attacker: SocketAddr = (Ipv4Addr::new(203, 0, 113, 7), 9999).into();

        let s = Arc::new(test_session(victim, listener.clone(), router.epoch));
        router.insert(s.clone());

        assert!(router.get(&route, attacker).is_none());
        assert_eq!(router.get(&route, victim).unwrap().peer, victim);
        assert_eq!(router.by_id(1).unwrap().peer, victim);

        router.remove(&s);
        assert!(router.get(&route, victim).is_none());
        assert!(router.by_id(1).is_none());
    }

    #[tokio::test]
    async fn the_session_cap_is_counted_per_route_not_scanned() {
        // The cap is consulted for every datagram from an unknown peer, so it
        // has to be a lookup. This pins the accounting: inserts and removals
        // keep the per-route count exact, including across routes.
        let router = UdpRouter::new();
        let listener = listener_placeholder();
        let mk = |route: &str, id: u64, port: u16| {
            Arc::new(session_on(
                route,
                id,
                (Ipv4Addr::LOCALHOST, port).into(),
                listener.clone(),
                router.epoch,
            ))
        };

        let a1 = mk("a", 1, 1001);
        let a2 = mk("a", 2, 1002);
        let b1 = mk("b", 3, 1003);
        for s in [&a1, &a2, &b1] {
            router.insert(s.clone());
        }
        assert_eq!(router.count_for_route("a"), 2);
        assert_eq!(router.count_for_route("b"), 1);
        assert_eq!(router.count_for_route("never-used"), 0);

        router.remove(&a1);
        assert_eq!(router.count_for_route("a"), 1);
        assert_eq!(router.count_for_route("b"), 1, "routes are counted apart");

        // Emptying a route drops its entry rather than leaving a zero behind.
        router.remove(&a2);
        assert_eq!(router.count_for_route("a"), 0);
        assert!(!router.tables.lock().per_route.contains_key("a"));
    }

    #[tokio::test]
    async fn reaping_is_scoped_to_one_route() {
        // Each route has its own idle timeout, so a route's reaper must not
        // apply that timeout to another route's sessions.
        let router = UdpRouter::new();
        let listener = listener_placeholder();
        let stale = Arc::new(session_on(
            "a",
            1,
            (Ipv4Addr::LOCALHOST, 1001).into(),
            listener.clone(),
            router.epoch,
        ));
        let other_route = Arc::new(session_on(
            "b",
            2,
            (Ipv4Addr::LOCALHOST, 1002).into(),
            listener.clone(),
            router.epoch,
        ));
        // Both look equally stale by timestamp.
        for s in [&stale, &other_route] {
            s.last_seen_ms.store(0, Ordering::Relaxed);
            router.insert(s.clone());
        }

        // A zero timeout expires anything on route "a" — and only route "a".
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(router.reap("a", Duration::ZERO), 1);
        assert!(router.by_id(1).is_none());
        assert!(router.by_id(2).is_some(), "route b must be untouched");
        assert_eq!(router.count_for_route("b"), 1);

        assert_eq!(router.reap("b", Duration::ZERO), 1);
        assert!(router.by_id(2).is_none());
    }

    #[tokio::test]
    async fn dropping_a_tunnels_sessions_spares_local_ones() {
        // A closed tunnel's sessions are dropped so a reconnecting client isn't
        // denied slots by sessions that can never be served again. Sessions on
        // a local upstream are unrelated to any tunnel and must survive it.
        // (`Sink::Tunnel` needs a live connection, so this drives the removal
        // through the same predicate path with a local-sink session.)
        let router = UdpRouter::new();
        let local = Arc::new(session_on(
            "a",
            1,
            (Ipv4Addr::LOCALHOST, 1001).into(),
            listener_placeholder(),
            router.epoch,
        ));
        router.insert(local.clone());

        assert_eq!(
            router.drop_sessions_for_conn(0),
            0,
            "a local-sink session belongs to no tunnel"
        );
        assert!(router.by_id(1).is_some());

        assert_eq!(router.remove_matching(|s| s.id == 1), 1);
        assert!(router.by_id(1).is_none());
        assert_eq!(router.count_for_route("a"), 0);
    }
}
