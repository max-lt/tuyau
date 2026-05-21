//! Listener / connection adapter (M5d, lib-first API layers 1-2).
//!
//! Wraps the layer-3 `accept_bi` raw-stream surface in types that hide
//! `quinn::*` from the public API. `TunnelConnection` impls
//! `AsyncRead + AsyncWrite` so it drops straight into anything expecting a
//! `tokio::net::TcpStream`-like; `TunnelListener` impls `axum::serve::Listener`
//! (behind the `axum` feature) so existing axum/hyper apps can be served over
//! the tunnel with a one-line swap.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use tuyau_protocol::{DataStreamHeader, TlsMode, read_frame};

use crate::error::ClientError;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

pin_project! {
    /// One server-initiated tunnel connection, presented as a plain duplex
    /// byte stream. The underlying QUIC stream pair is hidden — quinn version
    /// bumps stay non-breaking for downstream users.
    #[derive(Debug)]
    pub struct TunnelConnection {
        #[pin]
        send: quinn::SendStream,
        #[pin]
        recv: quinn::RecvStream,
        header: DataStreamHeader,
    }
}

impl TunnelConnection {
    /// Public hostname the tuyau-server routed this connection for.
    pub fn hostname(&self) -> &str {
        &self.header.hostname
    }

    /// Public peer address as the tuyau-server saw it (string form because
    /// QUIC may surface IPv6 + flow info). Use this for X-Forwarded-For or
    /// access logs.
    pub fn peer_addr(&self) -> &str {
        &self.header.peer_addr
    }

    /// TLS mode the tuyau-server applied for this hostname (terminated bytes
    /// are plaintext; passthrough bytes are opaque TLS).
    pub fn tls_mode(&self) -> TlsMode {
        self.header.mode
    }
}

impl AsyncRead for TunnelConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().recv.poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelConnection {
    // UFCS dispatch: `quinn::SendStream` has its own inherent `poll_write`
    // returning `quinn::WriteError`, so plain method calls would resolve to
    // the wrong one. Call the trait method explicitly.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(self.project().send, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(self.project().send, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(self.project().send, cx)
    }
}

/// A listener-shaped view over a tunnel connection. `accept()` yields one
/// `TunnelConnection` per server-initiated stream — the same primitive
/// `axum::serve` expects from a `TcpListener`.
#[derive(Debug, Clone)]
pub struct TunnelListener {
    conn: quinn::Connection,
}

impl TunnelListener {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Await the next incoming connection. Per-stream errors (bad header,
    /// timeout) are returned to the caller; connection-level errors
    /// (`QuicConnection`) mean the tunnel itself is gone.
    pub async fn accept(&self) -> Result<(TunnelConnection, SocketAddr), ClientError> {
        let (send, mut recv) = self.conn.accept_bi().await?;

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

        let peer_addr = header
            .peer_addr
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        Ok((TunnelConnection { send, recv, header }, peer_addr))
    }

    /// Placeholder address — a tunnel listener isn't bound to a local port.
    /// Exposed only because `axum::serve::Listener` requires it for startup
    /// logs.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Future that resolves when the underlying tunnel connection closes.
    /// Pair with `axum::serve(...).with_graceful_shutdown(listener.closed())`
    /// so the server stops accepting when the tunnel dies.
    pub fn closed(&self) -> impl Future<Output = ()> + Send + 'static {
        let conn = self.conn.clone();
        async move {
            let _ = conn.closed().await;
        }
    }
}

#[cfg(feature = "axum")]
impl axum::serve::Listener for TunnelListener {
    type Io = TunnelConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match TunnelListener::accept(self).await {
                Ok(pair) => return pair,
                Err(ClientError::QuicConnection(e)) => {
                    // Tunnel is gone; there are no future accepts. axum's
                    // `with_graceful_shutdown(listener.closed())` is the
                    // intended path out — block here so accept() never yields
                    // a phantom connection.
                    tracing::info!(error = %e, "tunnel listener: connection ended");
                    std::future::pending::<()>().await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "tunnel listener: skipping bad stream");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        TunnelListener::local_addr(self)
    }
}
