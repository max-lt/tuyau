use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{FramedRead, FramedWrite};

use tuyau_protocol::{ALPN, DataStreamHeader, FrameCodec, Hello, HelloResponse, read_frame};

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::verifier::PinningCertVerifier;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Mirror the server's tunnel-liveness values (tuyau-server src/server.rs): a
// short MAX_IDLE bounds how fast either side detects the other going silent,
// and KEEP_ALIVE sits well under it so a healthy tunnel is never falsely
// dropped.
const KEEP_ALIVE: Duration = Duration::from_secs(7);
const MAX_IDLE: Duration = Duration::from_secs(20);

/// An accepted server-initiated bidi stream, with its `DataStreamHeader` read
/// and the raw quinn streams ready for byte-level forwarding.
///
/// Note: this leaks `quinn::*` types deliberately — it's the "layer 3 / raw"
/// surface of the lib-first API. M5d will add `quinn`-free wrappers
/// (`tokio::io::AsyncRead`/`Listener` adapters) on top.
#[derive(Debug)]
pub struct TunnelStream {
    pub header: DataStreamHeader,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

#[derive(Debug)]
pub struct TunnelClient {
    connection: quinn::Connection,
    endpoint: Endpoint,
    ingress: Arc<HashMap<String, String>>,
}

impl TunnelClient {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let (host, _port) = split_host_port(&config.server_addr)?;

        let server_addr = tokio::net::lookup_host(&config.server_addr)
            .await
            .map_err(ClientError::Dns)?
            .next()
            .ok_or_else(|| ClientError::DnsEmpty(config.server_addr.clone()))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            PinningCertVerifier::new(config.server_cert_fingerprint_sha256, provider.clone());

        let mut rustls_config = RustlsClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(ClientError::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        rustls_config.alpn_protocols = vec![ALPN.to_vec()];

        let quic_crypto = QuicClientConfig::try_from(rustls_config)?;
        let mut quinn_config = QuinnClientConfig::new(Arc::new(quic_crypto));

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        transport.max_idle_timeout(Some(
            MAX_IDLE.try_into().expect("MAX_IDLE fits in a QUIC VarInt"),
        ));
        quinn_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("0.0.0.0:0 parses"))?;
        endpoint.set_default_client_config(quinn_config);

        tracing::info!(server_addr = %server_addr, host = %host, "connecting");
        let connecting = endpoint.connect(server_addr, host)?;
        let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(ClientError::QuicConnection(e)),
            Err(_) => return Err(ClientError::ConnectTimeout),
        };

        let ingress: HashMap<String, String> = config
            .ingress
            .iter()
            .map(|r| (r.host.clone(), r.local_addr.clone()))
            .collect();
        let ingress = Arc::new(ingress);

        let (send, recv) = connection.open_bi().await?;
        let mut writer = FramedWrite::new(send, FrameCodec::<Hello>::new());
        let mut reader = FramedRead::new(recv, FrameCodec::<HelloResponse>::new());

        writer
            .send(Hello {
                token: config.token,
                client_name: config.client_name,
            })
            .await?;

        let mut send_stream = writer.into_inner();
        let _ = send_stream.finish();

        let response = match tokio::time::timeout(HELLO_TIMEOUT, reader.next()).await {
            Ok(Some(Ok(r))) => r,
            Ok(Some(Err(e))) => return Err(ClientError::Protocol(e)),
            Ok(None) => return Err(ClientError::StreamClosedBeforeResponse),
            Err(_) => return Err(ClientError::ResponseTimeout),
        };

        match response {
            HelloResponse::Welcome => {
                tracing::info!(server_addr = %server_addr, "connected");
                Ok(Self {
                    connection,
                    endpoint,
                    ingress,
                })
            }
            HelloResponse::Reject { reason } => {
                tracing::warn!(reason = %reason, "server rejected");
                connection.close(0u32.into(), b"rejected");
                endpoint.close(0u32.into(), b"rejected");
                endpoint.wait_idle().await;
                Err(ClientError::Rejected(reason))
            }
        }
    }

    pub async fn wait_closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    /// Owned listener-shaped view over the tunnel — the entry point for the
    /// embedded / lib-first use case. Plug it into `axum::serve(listener,
    /// router)` (with the `axum` feature) or drive `accept()` manually for
    /// raw TCP-style services.
    ///
    /// Clones the underlying QUIC connection (cheap — internally an `Arc`).
    pub fn listener(&self) -> crate::TunnelListener {
        crate::TunnelListener::new(self.connection.clone())
    }

    /// Listener that terminates TLS over the tunnel with the app's own cert —
    /// the passthrough-mode counterpart to [`listener`](Self::listener). The
    /// server forwards raw TLS bytes; this app is the TLS endpoint.
    #[cfg(feature = "tls")]
    pub fn tls_listener(&self, acceptor: tokio_rustls::TlsAcceptor) -> crate::TlsTunnelListener {
        crate::TlsTunnelListener::new(self.listener(), acceptor)
    }

    /// Wait for the next server-initiated bidi stream and read its
    /// `DataStreamHeader` (first frame). Returns the header plus the raw
    /// stream halves for byte-level forwarding.
    ///
    /// In M5b this is the testing hook the public listener writes through.
    /// M5c will layer an internal accept loop + per-host forward to
    /// `local_addr` on top of this primitive.
    pub async fn accept_bi(&self) -> Result<TunnelStream, ClientError> {
        let (send, mut recv) = self.connection.accept_bi().await?;

        // Exact-length frame read: must NOT over-read into a buffer, since the
        // same stream carries opaque request bytes right after the header.
        let header = match tokio::time::timeout(
            HEADER_TIMEOUT,
            read_frame::<_, DataStreamHeader>(&mut recv),
        )
        .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => return Err(ClientError::Protocol(e)),
            Err(_) => return Err(ClientError::ResponseTimeout),
        };

        Ok(TunnelStream { header, send, recv })
    }

    /// Run the ingress forward loop until the tunnel connection ends.
    ///
    /// Accepts server-initiated streams, looks each up in the configured
    /// ingress map by hostname, dials the local service, and pipes bytes both
    /// ways. Per-stream failures (no ingress rule, local service down, bad
    /// header) are logged and the stream dropped — they do not stop the loop.
    /// Returns `Ok(())` when the tunnel connection closes (any reason); no
    /// reconnect is attempted (the orchestrator restarts the process).
    pub async fn serve(&self) -> Result<(), ClientError> {
        loop {
            match self.accept_bi().await {
                Ok(stream) => {
                    let ingress = Arc::clone(&self.ingress);
                    tokio::spawn(async move {
                        forward_stream(stream, ingress).await;
                    });
                }
                Err(ClientError::QuicConnection(e)) => {
                    tracing::info!(error = %e, "tunnel connection closed, serve loop ending");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "skipping malformed incoming stream");
                    continue;
                }
            }
        }
    }

    pub async fn shutdown(self) {
        self.connection.close(0u32.into(), b"client shutdown");
        self.endpoint.close(0u32.into(), b"client shutdown");
        self.endpoint.wait_idle().await;
    }
}

async fn forward_stream(stream: TunnelStream, ingress: Arc<HashMap<String, String>>) {
    let TunnelStream {
        header,
        mut send,
        mut recv,
    } = stream;

    let Some(local_addr) = ingress.get(&header.hostname) else {
        tracing::warn!(
            hostname = %header.hostname,
            "no ingress rule for hostname, dropping stream"
        );
        let _ = send.finish();
        return;
    };

    let local = match tokio::net::TcpStream::connect(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                hostname = %header.hostname,
                local_addr = %local_addr,
                error = %e,
                "failed to connect to local service, dropping stream"
            );
            let _ = send.finish();
            return;
        }
    };

    tracing::debug!(
        hostname = %header.hostname,
        local_addr = %local_addr,
        peer = %header.peer_addr,
        "forwarding stream to local service"
    );

    let (mut local_read, mut local_write) = local.into_split();

    let inbound = async move {
        let r = tokio::io::copy(&mut recv, &mut local_write).await;
        let _ = local_write.shutdown().await;
        r
    };
    let outbound = async move {
        let r = tokio::io::copy(&mut local_read, &mut send).await;
        let _ = send.finish();
        r
    };

    let (in_res, out_res) = tokio::join!(inbound, outbound);
    if let Err(e) = in_res {
        tracing::debug!(error = %e, "public→local copy ended with error");
    }
    if let Err(e) = out_res {
        tracing::debug!(error = %e, "local→public copy ended with error");
    }
}

fn split_host_port(s: &str) -> Result<(&str, &str), ClientError> {
    s.rsplit_once(':')
        .ok_or_else(|| ClientError::InvalidServerAddr(s.to_string()))
}
