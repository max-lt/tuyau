//! TLS-terminating listener adapter for passthrough-mode tunnels.
//!
//! In passthrough mode the tuyau-server forwards raw TLS bytes (it only peeks
//! the SNI); the embedding application is the TLS endpoint. [`TlsTunnelListener`]
//! wraps a [`TunnelListener`](crate::TunnelListener) with a
//! [`tokio_rustls::TlsAcceptor`] so each accepted tunnel stream is TLS-terminated
//! with the application's own certificate, yielding a decrypted byte stream.
//!
//! With the `axum` feature it also implements `axum::serve::Listener`, so a
//! passthrough app is the same one-liner as a terminated one:
//!
//! ```ignore
//! let listener = tunnel.tls_listener(acceptor);
//! axum::serve(listener, app)
//!     .with_graceful_shutdown(listener.closed())
//!     .await?;
//! ```

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::error::ClientError;
use crate::listener::{TunnelConnection, TunnelListener};

/// A [`TunnelListener`](crate::TunnelListener) that terminates TLS on each
/// accepted stream, yielding a decrypted [`TlsStream`].
#[derive(Clone)]
pub struct TlsTunnelListener {
    inner: TunnelListener,
    acceptor: TlsAcceptor,
}

impl TlsTunnelListener {
    /// Wrap a tunnel listener with the acceptor that holds the app's cert/key.
    pub fn new(inner: TunnelListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }

    /// Accept the next tunnel stream and complete the TLS handshake over it.
    /// Per-stream errors (bad header, header timeout, failed TLS handshake) are
    /// returned to the caller; `QuicConnection` means the tunnel itself is gone.
    pub async fn accept(&self) -> Result<(TlsStream<TunnelConnection>, SocketAddr), ClientError> {
        let (conn, addr) = self.inner.accept().await?;
        let tls = self.acceptor.accept(conn).await?; // io::Error -> ClientError::Io
        Ok((tls, addr))
    }

    /// Placeholder address — a tunnel listener isn't bound to a local port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Resolves when the underlying tunnel connection closes. Pair with
    /// `axum::serve(...).with_graceful_shutdown(listener.closed())`.
    pub fn closed(&self) -> impl Future<Output = ()> + Send + 'static {
        self.inner.closed()
    }
}

#[cfg(feature = "axum")]
impl axum::serve::Listener for TlsTunnelListener {
    type Io = TlsStream<TunnelConnection>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match TlsTunnelListener::accept(self).await {
                Ok(pair) => return pair,
                Err(ClientError::QuicConnection(e)) => {
                    // Tunnel gone; no future accepts. Block so accept() never
                    // yields a phantom connection — graceful shutdown via
                    // `closed()` is the intended exit.
                    tracing::info!(error = %e, "tls tunnel listener: connection ended");
                    std::future::pending::<()>().await;
                }
                Err(e) => {
                    // Bad header or failed TLS handshake on one stream — drop it
                    // and keep serving the rest.
                    tracing::warn!(error = %e, "tls tunnel listener: skipping stream");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        TlsTunnelListener::local_addr(self)
    }
}
