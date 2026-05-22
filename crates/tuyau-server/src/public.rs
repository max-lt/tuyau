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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::SinkExt;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::codec::FramedWrite;
use tokio_util::sync::CancellationToken;

use tuyau_protocol::{DataStreamHeader, FrameCodec, TlsMode};

use crate::cert::CertMaterial;
use crate::error::ServerError;
use crate::routes::RoutingTable;
use crate::sni::parse_sni;

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECORD_SIZE: usize = 16 * 1024;

pub(crate) struct PublicListenerHandle {
    pub local_addr: SocketAddr,
    pub join: JoinHandle<()>,
}

pub(crate) async fn start(
    listen_addr: SocketAddr,
    cert: CertMaterial,
    routes: RoutingTable,
    cancel: CancellationToken,
) -> Result<PublicListenerHandle, ServerError> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    let rustls_config = Arc::new(build_rustls_config(cert)?);

    let join = tokio::spawn(async move {
        accept_loop(listener, rustls_config, routes, cancel).await;
    });

    Ok(PublicListenerHandle { local_addr, join })
}

fn build_rustls_config(cert: CertMaterial) -> Result<RustlsServerConfig, ServerError> {
    let config = RustlsServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(ServerError::Tls)?
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert_der], cert.key_der)?;
    Ok(config)
}

async fn accept_loop(
    listener: TcpListener,
    rustls_config: Arc<RustlsServerConfig>,
    routes: RoutingTable,
    cancel: CancellationToken,
) {
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
                let rustls_config = rustls_config.clone();
                let routes = routes.clone();
                tokio::spawn(async move {
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

    // 3. Route lookup.
    let route = match routes.lookup(&sni) {
        Some(r) => r,
        None => {
            tracing::warn!(peer = %peer, sni = %sni, "no route for SNI, dropping");
            return Ok(());
        }
    };

    tracing::info!(
        peer = %peer,
        sni = %sni,
        mode = ?route.tls_mode,
        client_name = %route.client_name,
        "public connection routed"
    );

    // 4. Wrap stream so the ClientHello bytes we already read are replayed
    //    on the first reads.
    let prefixed = PrefixedStream::new(client_hello, stream);

    // 5. Open a QUIC bidi stream on the matching tunnel and send the header.
    let (send, recv) = match route.conn.open_bi().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "open_bi on tunnel failed");
            return Ok(());
        }
    };

    let header = DataStreamHeader {
        hostname: sni.clone(),
        peer_addr: peer.to_string(),
        mode: route.tls_mode,
    };
    let mut writer = FramedWrite::new(send, FrameCodec::<DataStreamHeader>::new());
    if let Err(e) = writer.send(header).await {
        tracing::warn!(peer = %peer, error = %e, "failed to send DataStreamHeader");
        return Ok(());
    }
    let send = writer.into_inner();

    // 6. Branch on TLS mode.
    match route.tls_mode {
        TlsMode::Terminated => {
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
            pipe_bytes(tls_stream, send, recv).await;
        }
        TlsMode::Passthrough => {
            // Forward raw TCP bytes (ClientHello included via PrefixedStream)
            // straight to the tunnel — no termination, no plaintext on this
            // box. This is the structural privacy guarantee.
            pipe_bytes(prefixed, send, recv).await;
        }
    }

    Ok(())
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
