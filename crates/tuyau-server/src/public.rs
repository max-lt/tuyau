//! Public TLS listener.
//!
//! Per-connection flow:
//!
//! 1. Read exactly one TLS record off the wire (the ClientHello).
//! 2. Parse the SNI from those bytes.
//! 3. Look up the matching tunnel in the routing table.
//! 4. Wrap the TCP stream in `PrefixedStream` that replays the ClientHello
//!    bytes we already consumed.
//! 5. Branch on TLS mode:
//!    - `Terminated`: feed the prefixed stream to `LazyConfigAcceptor`,
//!      complete TLS with the server's public cert, pipe plaintext over QUIC.
//!    - `Passthrough`: never terminate; pipe the raw bytes (ClientHello
//!      included) over QUIC straight to the owning client. The server never
//!      sees plaintext — the privacy property of the managed-B2B tier.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::SinkExt;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::server::ResolvesServerCert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::codec::FramedWrite;
use tokio_util::sync::CancellationToken;

use tuyau_protocol::{DataStreamHeader, FrameCodec};

use crate::error::ServerError;
use crate::routes::{Route, RouteEntry, RoutingTable, UpstreamTarget};
use crate::sni::parse_sni;

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECORD_SIZE: usize = 16 * 1024;
/// Pause after a failed `accept()` before retrying. A persistent error — notably
/// file-descriptor exhaustion (EMFILE/ENFILE), where `accept()` returns
/// immediately — would otherwise spin the loop at 100% CPU and starve every
/// other connection (including anything else this server fronts). A healthy
/// listener never takes this path, so the delay costs nothing in normal operation.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Default cap on concurrent public connections being handled (overridable via
/// `ServerConfig::max_public_connections`). Bounds memory / FDs under a flood.
pub(crate) const DEFAULT_MAX_PUBLIC_CONNECTIONS: usize = 1024;

/// Per-IP cap on concurrent public connections, derived from the global cap. A
/// single source IP can otherwise hold every global permit and starve everything
/// the server fronts (a connection-exhaustion DoS). The floor keeps it usable
/// when the global cap is tiny (tests), where the global limit binds first.
fn max_conns_per_ip(global: usize) -> usize {
    (global / 8).max(16)
}

/// Counts concurrent public connections per source IP and refuses new ones past
/// the cap. A held [`IpPermit`] is one live connection; the count is decremented
/// (and the entry dropped at zero, so the map stays bounded by live IPs) when it
/// is dropped. parking_lot Mutex — non-poisoning, like the routing table.
#[derive(Clone)]
struct PerIpLimiter {
    max_per_ip: usize,
    counts: Arc<parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
}

struct IpPermit {
    ip: std::net::IpAddr,
    counts: Arc<parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
}

impl PerIpLimiter {
    fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            counts: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Reserve a slot for `ip`, or `None` if it's already at the cap. A fresh IP
    /// (count 0) is always below the cap (cap ≥ 1), so this never leaves a 0 entry.
    fn try_acquire(&self, ip: std::net::IpAddr) -> Option<IpPermit> {
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

pub(crate) struct PublicListenerHandle {
    pub local_addr: SocketAddr,
    pub join: JoinHandle<()>,
}

pub(crate) async fn start(
    listen_addr: SocketAddr,
    cert_resolver: Arc<dyn ResolvesServerCert>,
    acme_active: bool,
    routes: RoutingTable,
    max_conns: usize,
    error_502: Arc<str>,
    cancel: CancellationToken,
) -> Result<PublicListenerHandle, ServerError> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let rustls_config = Arc::new(build_rustls_config(cert_resolver, acme_active)?);

    let join = tokio::spawn(async move {
        accept_loop(
            listener,
            rustls_config,
            routes,
            max_conns,
            error_502,
            cancel,
        )
        .await;
    });

    Ok(PublicListenerHandle { local_addr, join })
}

fn build_rustls_config(
    cert_resolver: Arc<dyn ResolvesServerCert>,
    acme_active: bool,
) -> Result<RustlsServerConfig, ServerError> {
    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(ServerError::Tls)?
    .with_no_client_auth()
    .with_cert_resolver(cert_resolver);
    // Advertise `h2` then `http/1.1` (preference order). We accept h2 from any
    // client because terminated mode now bridges h2→h1: we terminate h2 here and
    // talk h1 to the backend (see `h2proxy`), so the backend never needs to speak
    // h2. Once alpn_protocols is non-empty, rustls rejects a client with no
    // overlap via a fatal NoApplicationProtocol alert — browsers always offer
    // h2/http/1.1, so they always match.
    config.alpn_protocols.push(b"h2".to_vec());
    config.alpn_protocols.push(b"http/1.1".to_vec());
    if acme_active {
        // Then `acme-tls/1` so Let's Encrypt's validator picks it during
        // TLS-ALPN-01 challenges and rustls-acme's resolver can answer. ACME
        // validators offer only this, so ordering never collides with browsers.
        config
            .alpn_protocols
            .push(rustls_acme::acme::ACME_TLS_ALPN_NAME.to_vec());
    }
    Ok(config)
}

async fn accept_loop(
    listener: TcpListener,
    rustls_config: Arc<RustlsServerConfig>,
    routes: RoutingTable,
    max_conns: usize,
    error_502: Arc<str>,
    cancel: CancellationToken,
) {
    // Bounds the number of public connections handled at once. A permit is held
    // for a connection's whole lifetime; when none are free, new connections are
    // shed rather than queued, so a flood can't grow tasks/memory without bound.
    let limiter = Arc::new(Semaphore::new(max_conns));
    // Plus a per-IP cap so a single source can't hold every global permit and
    // starve the rest (including anything else this server fronts).
    let per_ip = PerIpLimiter::new(max_conns_per_ip(max_conns));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("public accept loop cancelled");
                break;
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(x) => x,
                    Err(e) => {
                        // Back off so a persistent error (e.g. FD exhaustion)
                        // can't spin the loop at 100% CPU and starve everything.
                        tracing::warn!(error = %e, "public accept failed; backing off");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let permit = match limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // At capacity: drop the stream (closes it) and move on.
                        tracing::debug!(peer = %peer, "public connection cap reached, shedding");
                        drop(stream);
                        continue;
                    }
                };
                // Per-IP cap: a single source can hold at most its share, so it
                // can't monopolise the global pool. Shed (not queue) past it.
                let ip_permit = match per_ip.try_acquire(peer.ip()) {
                    Some(p) => p,
                    None => {
                        tracing::debug!(peer = %peer, "per-IP connection cap reached, shedding");
                        drop(stream);
                        continue;
                    }
                };
                let rustls_config = rustls_config.clone();
                let routes = routes.clone();
                let error_502 = error_502.clone();
                tokio::spawn(async move {
                    let _permit = permit; // released when this connection ends
                    let _ip_permit = ip_permit; // decrements the per-IP count on end
                    if let Err(e) = handle_public(stream, peer, rustls_config, routes, error_502).await {
                        tracing::warn!(peer = %peer, error = %e, "public connection error");
                    }
                });
            }
        }
    }
}

async fn handle_public(
    mut stream: TcpStream,
    peer: SocketAddr,
    rustls_config: Arc<RustlsServerConfig>,
    routes: RoutingTable,
    error_502: Arc<str>,
) -> io::Result<()> {
    // 1. Read the ClientHello record off the wire (NOT peeking — consumed
    //    bytes are replayed below via PrefixedStream so both terminated and
    //    passthrough paths see the same stream the client sent).
    let client_hello =
        match tokio::time::timeout(CLIENT_HELLO_TIMEOUT, read_client_hello(&mut stream)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(io::Error::other(format!("ClientHello read: {e}"))),
            Err(_) => return Err(io::Error::other("ClientHello read timeout")),
        };

    // 2. Parse SNI.
    let Some(sni) = parse_sni(&client_hello) else {
        tracing::warn!(peer = %peer, "no SNI in ClientHello, dropping");
        return Ok(());
    };

    // 3. Wrap the stream so the ClientHello bytes we already read are replayed.
    let prefixed = PrefixedStream::new(client_hello, stream);

    // 4. Decide from the KNOWN terminated set (config + the dynamic seam), NOT a
    //    live route: a provisioned terminated hostname is terminated even when no
    //    tunnel is routing it yet — so its ACME challenge / cert is served (the
    //    cert is for the domain, independent of any agent). Only a *real* request
    //    then continues to the live backend.
    if routes.is_terminated(&sni) {
        let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), prefixed);
        let start_handshake = match tokio::time::timeout(TLS_ACCEPT_TIMEOUT, acceptor).await {
            Ok(Ok(sh)) => sh,
            Ok(Err(e)) => {
                tracing::warn!(peer = %peer, sni = %sni, error = %e, "TLS accept failed");
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(peer = %peer, sni = %sni, "TLS accept timeout");
                return Ok(());
            }
        };
        let tls_stream = match start_handshake.into_stream(rustls_config).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(peer = %peer, sni = %sni, error = %e, "TLS handshake failed");
                return Ok(());
            }
        };

        // ACME TLS-ALPN-01 challenge: the resolver answered with the challenge
        // cert, the validator closes. No backend dispatch — bail.
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        if alpn == Some(rustls_acme::acme::ACME_TLS_ALPN_NAME) {
            tracing::info!(peer = %peer, sni = %sni, "acme-tls/1 challenge served");
            return Ok(());
        }

        // h2 negotiated → can't byte-pipe (the backend speaks h1). Terminate h2
        // and reverse-proxy each request to the backend as h1.
        if alpn == Some(b"h2".as_slice()) {
            tracing::info!(peer = %peer, sni = %sni, "public connection routed (terminated, h2→h1)");
            crate::h2proxy::serve_h2(
                tls_stream,
                routes.clone(),
                sni.clone(),
                peer,
                error_502.clone(),
            )
            .await;
            return Ok(());
        }

        // Real request → forward plaintext to the live backend, or close if none.
        match routes.lookup(&sni) {
            Some(Route::Tunnel(entry)) => {
                tracing::info!(peer = %peer, sni = %sni, target = %format!("tunnel:{}", entry.client_name), "public connection routed (terminated)");
                if let Some((send, recv)) = open_tunnel_stream(&entry, &sni, peer).await {
                    pipe_bytes(tls_stream, send, recv).await;
                }
            }
            Some(Route::Local { target, .. }) => {
                tracing::info!(peer = %peer, sni = %sni, "public connection routed (terminated, local)");
                dispatch_local(tls_stream, &target, &sni, peer).await;
            }
            None => {
                tracing::info!(peer = %peer, sni = %sni, "terminated, no live route — serving 502");
                write_502(tls_stream, &error_502).await;
            }
        }
    } else {
        // Passthrough — forward raw bytes (ClientHello included). No termination,
        // no plaintext on this box: the privacy guarantee. The downstream (tunnel
        // or local upstream) terminates its own TLS.
        match routes.lookup(&sni) {
            Some(Route::Tunnel(entry)) => {
                tracing::info!(peer = %peer, sni = %sni, target = %format!("tunnel:{}", entry.client_name), "public connection routed (passthrough)");
                if let Some((send, recv)) = open_tunnel_stream(&entry, &sni, peer).await {
                    pipe_bytes(prefixed, send, recv).await;
                }
            }
            Some(Route::Local { target, .. }) => {
                tracing::info!(peer = %peer, sni = %sni, "public connection routed (passthrough, local)");
                dispatch_local(prefixed, &target, &sni, peer).await;
            }
            None => {
                tracing::warn!(peer = %peer, sni = %sni, "no route for SNI, dropping");
            }
        }
    }

    Ok(())
}

/// Connect to a local upstream's target and splice the public-side stream to it.
/// Generic over the public stream so both terminated TLS streams and raw
/// passthrough streams reuse it.
async fn dispatch_local<S>(public_stream: S, target: &UpstreamTarget, sni: &str, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match target {
        UpstreamTarget::Tcp(addr) => {
            if let Some(up) = connect_tcp(*addr, sni, peer).await {
                splice_local(public_stream, up).await;
            }
        }
        UpstreamTarget::Unix(path) => {
            if let Some(up) = connect_unix(path, sni, peer).await {
                splice_local(public_stream, up).await;
            }
        }
    }
}

/// Dial a local upstream over TCP, with a timeout. `None` on failure (logged).
pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    sni: &str,
    peer: SocketAddr,
) -> Option<TcpStream> {
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer, sni = %sni, %addr, error = %e, "local upstream connect failed");
            None
        }
        Err(_) => {
            tracing::warn!(peer = %peer, sni = %sni, %addr, "local upstream connect timeout");
            None
        }
    }
}

/// Dial a local upstream over a Unix domain socket, with a timeout. `None` on
/// failure (logged).
pub(crate) async fn connect_unix(path: &Path, sni: &str, peer: SocketAddr) -> Option<UnixStream> {
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer, sni = %sni, socket = %path.display(), error = %e, "local upstream connect failed");
            None
        }
        Err(_) => {
            tracing::warn!(peer = %peer, sni = %sni, socket = %path.display(), "local upstream connect timeout");
            None
        }
    }
}

/// The built-in 502 page, served when a deployment doesn't supply its own via
/// [`ServerConfig::error_502_file`](crate::config::ServerConfig::error_502_file).
pub(crate) const DEFAULT_502_HTML: &str = include_str!("502.html");

/// Write a friendly HTTP 502 on a terminated (already-decrypted) stream when the
/// hostname is configured but no backend is currently serving it. Only possible
/// in terminated mode — passthrough never decrypts, so it can only drop.
async fn write_502<S: AsyncWrite + Unpin>(mut stream: S, body: &str) {
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\n\
         content-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// Splice a public-side stream to a local upstream, copying both directions
/// until either end closes. Both sides are plain byte streams (no QUIC framing),
/// so a single `copy_bidirectional` does it.
async fn splice_local<A, B>(mut public_stream: A, mut upstream: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = tokio::io::copy_bidirectional(&mut public_stream, &mut upstream).await {
        tracing::debug!(error = %e, "local upstream splice ended with error");
    }
}

/// Open a bidi QUIC stream on the matched tunnel and send the
/// `DataStreamHeader` as the first frame. Returns `None` on any failure
/// (logged); caller drops the connection.
pub(crate) async fn open_tunnel_stream(
    route: &RouteEntry,
    sni: &str,
    peer: SocketAddr,
) -> Option<(quinn::SendStream, quinn::RecvStream)> {
    let (send, recv) = match route.conn.open_bi().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "open_bi on tunnel failed");
            return None;
        }
    };
    let header = DataStreamHeader {
        hostname: sni.to_string(),
        peer_addr: peer.to_string(),
        mode: route.tls_mode,
    };
    let mut writer = FramedWrite::new(send, FrameCodec::<DataStreamHeader>::new());
    if let Err(e) = writer.send(header).await {
        tracing::warn!(peer = %peer, error = %e, "failed to send DataStreamHeader");
        return None;
    }
    Some((writer.into_inner(), recv))
}

/// Read exactly one TLS record from `stream` into a Vec (header + body).
/// Caps at `MAX_RECORD_SIZE` so a malicious or malformed length field can't
/// allocate unbounded memory.
async fn read_client_hello(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 5];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x16 {
        return Err(io::Error::other(format!(
            "not a TLS Handshake record (type=0x{:02x})",
            buf[0]
        )));
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len > MAX_RECORD_SIZE {
        return Err(io::Error::other(format!(
            "ClientHello record too large: {rec_len} bytes"
        )));
    }
    buf.resize(5 + rec_len, 0);
    stream.read_exact(&mut buf[5..]).await?;
    Ok(buf)
}

/// Wraps an `AsyncRead + AsyncWrite` stream and replays a fixed byte prefix on
/// the read side before delegating to the inner stream. Writes always go to
/// the inner stream. Used here to "give back" the ClientHello bytes we
/// already consumed in `read_client_hello`.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    consumed: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            consumed: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.consumed < self.prefix.len() {
            let remaining = &self.prefix[self.consumed..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.consumed += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Pipe bytes between an `AsyncRead + AsyncWrite` public-side stream and the
/// tunnel's QUIC stream pair. Each direction copies until EOF on its source,
/// then finishes the destination. Generic so both terminated TLS streams and
/// raw passthrough streams use the same plumbing.
async fn pipe_bytes<S>(
    public_stream: S,
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut pub_read, mut pub_write) = split(public_stream);

    let up = async move {
        let res = tokio::io::copy(&mut pub_read, &mut quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let down = async move {
        let res = tokio::io::copy(&mut quic_recv, &mut pub_write).await;
        let _ = pub_write.shutdown().await;
        res
    };

    let (up_res, down_res) = tokio::join!(up, down);
    if let Err(e) = up_res {
        tracing::debug!(error = %e, "public→tunnel copy ended with error");
    }
    if let Err(e) = down_res {
        tracing::debug!(error = %e, "tunnel→public copy ended with error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn per_ip_limiter_caps_and_releases() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let lim = PerIpLimiter::new(2);

        let a = lim.try_acquire(ip).expect("1st under cap");
        let b = lim.try_acquire(ip).expect("2nd under cap");
        assert!(lim.try_acquire(ip).is_none(), "3rd from same IP is capped");
        // A different IP is unaffected by the first IP's count.
        let c = lim.try_acquire(other).expect("other IP independent");

        drop(b); // free one slot for `ip`
        let d = lim.try_acquire(ip).expect("slot freed → acquire again");

        drop(a);
        drop(d);
        drop(c);
        // All released: the map drops emptied IPs, so it's back to empty.
        assert!(lim.counts.lock().is_empty(), "map must not leak IP entries");
    }

    #[test]
    fn per_ip_cap_derives_from_global_with_floor() {
        assert_eq!(max_conns_per_ip(1024), 128);
        assert_eq!(max_conns_per_ip(1), 16); // floor for tiny/global-bound caps
    }
}
