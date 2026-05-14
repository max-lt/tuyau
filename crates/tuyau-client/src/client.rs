use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use tokio_util::codec::{FramedRead, FramedWrite};

use tuyau_protocol::{ALPN, FrameCodec, Hello, HelloResponse};

use crate::config::ClientConfig;
use crate::error::ClientError;
use crate::verifier::PinningCertVerifier;

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const MAX_IDLE: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct TunnelClient {
    connection: quinn::Connection,
    endpoint: Endpoint,
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

    pub async fn wait_closed(self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    pub async fn shutdown(self) {
        self.connection.close(0u32.into(), b"client shutdown");
        self.endpoint.close(0u32.into(), b"client shutdown");
        self.endpoint.wait_idle().await;
    }
}

fn split_host_port(s: &str) -> Result<(&str, &str), ClientError> {
    s.rsplit_once(':')
        .ok_or_else(|| ClientError::InvalidServerAddr(s.to_string()))
}
