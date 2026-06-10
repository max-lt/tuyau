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

/// Default cap on concurrent public connections being handled (overridable via
/// `ServerConfig::max_public_connections`). Bounds memory / FDs under a flood.
pub(crate) const DEFAULT_MAX_PUBLIC_CONNECTIONS: usize = 1024;

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
    cancel: CancellationToken,
) -> Result<PublicListenerHandle, ServerError> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let rustls_config = Arc::new(build_rustls_config(cert_resolver, acme_active)?);

    let join = tokio::spawn(async move {
        accept_loop(listener, rustls_config, routes, max_conns, cancel).await;
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
    if acme_active {
        // Advertise `http/1.1` first so ordinary clients (browsers always send
        // an ALPN list of h2/http/1.1) find a common protocol — once
        // alpn_protocols is non-empty, rustls rejects any client with no
        // overlap via a fatal NoApplicationProtocol alert. We only offer
        // http/1.1 (not h2): terminated mode is a transparent byte-pipe to an
        // arbitrary backend, and http/1.1 is universally understood.
        config.alpn_protocols.push(b"http/1.1".to_vec());
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
    cancel: CancellationToken,
) {
    // Bounds the number of public connections handled at once. A permit is held
    // for a connection's whole lifetime; when none are free, new connections are
    // shed rather than queued, so a flood can't grow tasks/memory without bound.
    let limiter = Arc::new(Semaphore::new(max_conns));
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
                        tracing::warn!(error = %e, "public accept failed");
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
                let rustls_config = rustls_config.clone();
                let routes = routes.clone();
                tokio::spawn(async move {
                    let _permit = permit; // released when this connection ends
                    if let Err(e) = handle_public(stream, peer, rustls_config, routes).await {
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
        if tls_stream.get_ref().1.alpn_protocol() == Some(rustls_acme::acme::ACME_TLS_ALPN_NAME) {
            tracing::info!(peer = %peer, sni = %sni, "acme-tls/1 challenge served");
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
                tracing::info!(peer = %peer, sni = %sni, "terminated cert served but no live route (agent offline?)");
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
async fn connect_tcp(addr: SocketAddr, sni: &str, peer: SocketAddr) -> Option<TcpStream> {
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
async fn connect_unix(path: &Path, sni: &str, peer: SocketAddr) -> Option<UnixStream> {
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
async fn open_tunnel_stream(
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
