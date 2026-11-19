//! Internal upstreams: an upstream with `internal_listener = "<name>"` reaches
//! the [`InternalUpstream`] that the embedding program set under that name.
//! The core gives it the facts of each public connection and takes a byte
//! stream back; where the stream leads is up to the embedder.
//!
//! [`InternalListener::channel`] is one such upstream: an in-memory stream to a
//! listener in the same process.

// Only an embedder sets an upstream (`dynamic`); without it, nothing does
#![cfg_attr(not(feature = "dynamic"), allow(dead_code))]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

use crate::config::TlsMode;
use crate::public::UPSTREAM_CONNECT_TIMEOUT;

/// What the core knows of a public connection routed to an internal upstream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InternalConnect {
    /// The `internal_listener` of the upstream entry.
    pub name: String,
    /// The SNI of the public connection.
    pub hostname: String,
    /// The address of the public client.
    pub peer: SocketAddr,
    pub tls_mode: TlsMode,
}

/// The byte stream an [`InternalUpstream`] gives back: the plaintext HTTP of a
/// `terminated` host, the plaintext of a `tls_offload` host, or the raw TLS of
/// a `passthrough` host.
pub trait InternalStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> InternalStream for T {}

/// Serves the upstreams with `internal_listener = "<name>"`, set with
/// [`TunnelServer::set_internal_upstream`](crate::TunnelServer::set_internal_upstream).
/// An error gets the client a 502, as a stopped `local_addr` does.
#[async_trait]
pub trait InternalUpstream: Send + Sync + 'static {
    async fn open(&self, connect: InternalConnect) -> io::Result<Box<dyn InternalStream>>;
}

/// The internal upstreams of a server, by name.
#[derive(Clone, Default)]
pub(crate) struct Internal {
    upstreams: Arc<RwLock<HashMap<String, Arc<dyn InternalUpstream>>>>,
}

impl Internal {
    pub(crate) fn set(&self, name: &str, upstream: Arc<dyn InternalUpstream>) {
        self.upstreams.write().insert(name.to_owned(), upstream);
    }

    pub(crate) fn remove(&self, name: &str) {
        self.upstreams.write().remove(name);
    }

    pub(crate) fn clear(&self) {
        self.upstreams.write().clear();
    }

    /// `None` when no upstream has that name, or when it fails or does not
    /// answer in time (logged).
    pub(crate) async fn connect(
        &self,
        name: &str,
        hostname: &str,
        peer: SocketAddr,
        tls_mode: TlsMode,
    ) -> Option<Box<dyn InternalStream>> {
        let upstream = self.upstreams.read().get(name).cloned();
        let Some(upstream) = upstream else {
            tracing::warn!(peer = %peer, sni = %hostname, upstream = name, "no internal upstream");
            return None;
        };

        let connect = InternalConnect {
            name: name.to_owned(),
            hostname: hostname.to_owned(),
            peer,
            tls_mode,
        };
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, upstream.open(connect)).await {
            Ok(Ok(stream)) => Some(stream),
            Ok(Err(e)) => {
                tracing::warn!(peer = %peer, sni = %hostname, upstream = name, error = %e, "internal upstream open failed");
                None
            }
            Err(_) => {
                tracing::warn!(peer = %peer, sni = %hostname, upstream = name, "internal upstream open timeout");
                None
            }
        }
    }
}

/// Bytes in flight each way on one in-memory connection before a writer waits.
const STREAM_BUFFER: usize = 64 * 1024;

/// Connections an [`InternalListener`] holds before `accept`, as the backlog
/// of a socket.
const BACKLOG: usize = 128;

/// The connections of an [`InMemoryUpstream`], in the same process.
pub struct InternalListener {
    receiver: mpsc::Receiver<InternalConnection>,
}

/// The [`InternalUpstream`] half of [`InternalListener::channel`].
#[derive(Clone)]
pub struct InMemoryUpstream {
    sender: mpsc::Sender<InternalConnection>,
}

impl InternalListener {
    /// An upstream to set on the server, and the listener of its connections.
    /// Once the listener drops, the upstream fails each connection.
    pub fn channel() -> (InMemoryUpstream, InternalListener) {
        let (sender, receiver) = mpsc::channel(BACKLOG);
        (InMemoryUpstream { sender }, InternalListener { receiver })
    }

    /// The next connection. `None` once every [`InMemoryUpstream`] has dropped.
    pub async fn accept(&mut self) -> Option<InternalConnection> {
        self.receiver.recv().await
    }
}

#[async_trait]
impl InternalUpstream for InMemoryUpstream {
    async fn open(&self, connect: InternalConnect) -> io::Result<Box<dyn InternalStream>> {
        let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
        let connection = InternalConnection {
            stream: theirs,
            connect,
        };
        self.sender
            .send(connection)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "listener dropped"))?;
        Ok(Box::new(ours))
    }
}

/// One connection of an [`InternalListener`].
pub struct InternalConnection {
    stream: DuplexStream,
    connect: InternalConnect,
}

impl InternalConnection {
    pub fn connect(&self) -> &InternalConnect {
        &self.connect
    }
}

impl AsyncRead for InternalConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for InternalConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// `axum::serve(listener, app)`. axum gives `ConnectInfo<SocketAddr>`, the
/// address of the public client, through its `TapIo` wrapper only:
///
/// ```ignore
/// use axum::serve::ListenerExt;
///
/// let app = app.into_make_service_with_connect_info::<SocketAddr>();
/// axum::serve(listener.tap_io(|_| ()), app).await?;
/// ```
#[cfg(feature = "axum")]
impl axum::serve::Listener for InternalListener {
    type Io = InternalConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match InternalListener::accept(self).await {
            Some(connection) => {
                let peer = connection.connect.peer;
                (connection, peer)
            }
            // axum retries an accept forever: once the upstream drops, wait for good
            None => std::future::pending().await,
        }
    }

    /// No socket: an unspecified address, for the start log of axum.
    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn peer() -> SocketAddr {
        "203.0.113.7:50000".parse().unwrap()
    }

    #[tokio::test]
    async fn test_a_connection_reaches_the_listener_with_its_facts() {
        let internal = Internal::default();
        let (upstream, mut listener) = InternalListener::channel();
        internal.set("admin", Arc::new(upstream));

        let mut ours = internal
            .connect("admin", "admin.example.com", peer(), TlsMode::Terminated)
            .await
            .unwrap();
        let mut theirs = listener.accept().await.unwrap();
        ours.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        theirs.read_exact(&mut got).await.unwrap();

        assert_eq!(&got, b"ping");
        assert_eq!(theirs.connect().name, "admin");
        assert_eq!(theirs.connect().hostname, "admin.example.com");
        assert_eq!(theirs.connect().peer, peer());
        assert_eq!(theirs.connect().tls_mode, TlsMode::Terminated);
    }

    #[tokio::test]
    async fn test_an_unknown_or_removed_name_gets_no_stream() {
        let internal = Internal::default();
        let (upstream, _listener) = InternalListener::channel();
        internal.set("admin", Arc::new(upstream));
        internal.remove("admin");

        let stream = internal
            .connect("admin", "admin.example.com", peer(), TlsMode::Terminated)
            .await;

        assert!(stream.is_none());
    }

    #[tokio::test]
    async fn test_a_dropped_listener_gets_no_stream() {
        let internal = Internal::default();
        let (upstream, listener) = InternalListener::channel();
        internal.set("admin", Arc::new(upstream));
        drop(listener);

        let stream = internal
            .connect("admin", "admin.example.com", peer(), TlsMode::Terminated)
            .await;

        assert!(stream.is_none());
    }

    #[tokio::test]
    async fn test_clear_ends_accept() {
        let internal = Internal::default();
        let (upstream, mut listener) = InternalListener::channel();
        internal.set("admin", Arc::new(upstream));

        internal.clear();

        assert!(listener.accept().await.is_none());
    }
}
