//! Public TLS listener (M5b).
//!
//! Listens on a TCP port for incoming public traffic, peeks the SNI from the
//! ClientHello, looks up the matching tunnel in the routing table, terminates
//! TLS with the server's self-signed public cert, then opens a new bidi QUIC
//! stream on that tunnel and pipes bytes both ways. The first frame on the
//! new stream is a `DataStreamHeader` describing the hostname / public peer /
//! TLS mode so the tunnel client knows what it's serving.
//!
//! Passthrough mode is not implemented in M5b — entries marked passthrough are
//! logged and dropped at the public-side handshake. They will be wired in M5f.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncWriteExt, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::codec::FramedWrite;
use tokio_util::sync::CancellationToken;

use tuyau_protocol::{DataStreamHeader, FrameCodec, TlsMode};

use crate::cert::CertMaterial;
use crate::error::ServerError;
use crate::routes::RoutingTable;

const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);

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
    // Intentionally no ALPN: we tunnel raw bytes and let the local service
    // negotiate its own protocol. Adding h2/http/1.1 here would force a
    // protocol on the tunneled service that it might not implement.
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
    stream: TcpStream,
    peer: SocketAddr,
    rustls_config: Arc<RustlsServerConfig>,
    routes: RoutingTable,
) -> io::Result<()> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);

    let start_handshake = match tokio::time::timeout(TLS_ACCEPT_TIMEOUT, acceptor).await {
        Ok(Ok(sh)) => sh,
        Ok(Err(e)) => return Err(io::Error::other(format!("client hello read: {e}"))),
        Err(_) => return Err(io::Error::other("client hello timeout")),
    };

    let sni = start_handshake
        .client_hello()
        .server_name()
        .map(|s| s.to_string());

    let Some(sni) = sni else {
        tracing::warn!(peer = %peer, "no SNI in ClientHello, dropping");
        return Ok(());
    };

    let route = match routes.lookup(&sni) {
        Some(r) => r,
        None => {
            tracing::warn!(peer = %peer, sni = %sni, "no route for SNI, dropping");
            return Ok(());
        }
    };

    if route.tls_mode != TlsMode::Terminated {
        tracing::warn!(
            peer = %peer,
            sni = %sni,
            "passthrough mode not implemented in M5b (M5f), dropping"
        );
        return Ok(());
    }

    let tls_stream = match start_handshake.into_stream(rustls_config).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "TLS handshake failed");
            return Ok(());
        }
    };

    tracing::info!(
        peer = %peer,
        sni = %sni,
        client_name = %route.client_name,
        "public connection routed"
    );

    // Open a new bidi QUIC stream on the matched tunnel connection.
    let (send, recv) = match route.conn.open_bi().await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "open_bi on tunnel failed");
            return Ok(());
        }
    };

    // Send DataStreamHeader as the first frame on the new stream.
    let header = DataStreamHeader {
        hostname: sni,
        peer_addr: peer.to_string(),
        mode: TlsMode::Terminated,
    };
    let mut writer = FramedWrite::new(send, FrameCodec::<DataStreamHeader>::new());
    if let Err(e) = writer.send(header).await {
        tracing::warn!(peer = %peer, error = %e, "failed to send DataStreamHeader");
        return Ok(());
    }
    let send = writer.into_inner();

    pipe_bytes(tls_stream, send, recv).await;
    Ok(())
}

/// Pipe bytes between the public TLS stream and the tunnel's QUIC stream pair.
/// Each direction copies until EOF on its source, then finishes the destination.
async fn pipe_bytes(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
) {
    let (mut tls_read, mut tls_write) = split(tls_stream);

    let up = async move {
        let res = tokio::io::copy(&mut tls_read, &mut quic_send).await;
        let _ = quic_send.finish();
        res
    };

    let down = async move {
        let res = tokio::io::copy(&mut quic_recv, &mut tls_write).await;
        let _ = tls_write.shutdown().await;
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
