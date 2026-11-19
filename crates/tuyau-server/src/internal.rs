//! Internal listeners: an upstream with `internal_listener = "<name>"` reaches
//! the [`InternalListener`] that the embedding program took under that name,
//! over an in-memory stream instead of a socket.

// Only an embedder takes a listener (`dynamic`); without it, nothing does
#![cfg_attr(not(feature = "dynamic"), allow(dead_code))]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

use crate::config::TlsMode;
use crate::error::ServerError;
use crate::public::UPSTREAM_CONNECT_TIMEOUT;

/// Bytes in flight each way on one connection before a writer waits.
const STREAM_BUFFER: usize = 64 * 1024;

/// Connections a listener holds before `accept`, as the backlog of a socket.
const BACKLOG: usize = 128;

struct Slot {
    id: u64,
    sender: mpsc::Sender<InternalConnection>,
}

/// The internal listeners of a server, by name.
#[derive(Clone, Default)]
pub(crate) struct Internal {
    slots: Arc<Mutex<HashMap<String, Slot>>>,
    next_id: Arc<AtomicU64>,
}

impl Internal {
    pub(crate) fn listen(&self, name: &str) -> Result<InternalListener, ServerError> {
        let mut slots = self.slots.lock();
        if slots.contains_key(name) {
            return Err(ServerError::InternalListenerTaken(name.to_owned()));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(BACKLOG);
        slots.insert(name.to_owned(), Slot { id, sender });

        Ok(InternalListener {
            name: name.to_owned(),
            id,
            receiver,
            internal: self.clone(),
        })
    }

    /// The server side of a new connection to the listener `name`. `None` when
    /// no listener has that name, or when it does not accept in time (logged).
    pub(crate) async fn connect(
        &self,
        name: &str,
        sni: &str,
        peer: SocketAddr,
        tls_mode: TlsMode,
    ) -> Option<DuplexStream> {
        let sender = self.slots.lock().get(name).map(|s| s.sender.clone());
        let Some(sender) = sender else {
            tracing::warn!(peer = %peer, sni = %sni, listener = name, "no internal listener");
            return None;
        };

        let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
        let connection = InternalConnection {
            stream: theirs,
            hostname: sni.to_owned(),
            peer,
            tls_mode,
        };
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, sender.send(connection)).await {
            Ok(Ok(())) => Some(ours),
            Ok(Err(_)) => {
                tracing::warn!(peer = %peer, sni = %sni, listener = name, "internal listener closed");
                None
            }
            Err(_) => {
                tracing::warn!(peer = %peer, sni = %sni, listener = name, "internal listener connect timeout");
                None
            }
        }
    }

    /// Ends every listener: `accept` returns `None` once its backlog is empty.
    pub(crate) fn close(&self) {
        self.slots.lock().clear();
    }
}

/// The connections that the server routes to an upstream with
/// `internal_listener = "<name>"`. Dropping it frees the name.
pub struct InternalListener {
    name: String,
    id: u64,
    receiver: mpsc::Receiver<InternalConnection>,
    internal: Internal,
}

impl InternalListener {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The next connection. `None` after the server shuts down.
    pub async fn accept(&mut self) -> Option<InternalConnection> {
        self.receiver.recv().await
    }
}

impl Drop for InternalListener {
    fn drop(&mut self) {
        let mut slots = self.internal.slots.lock();
        if slots.get(&self.name).is_some_and(|s| s.id == self.id) {
            slots.remove(&self.name);
        }
    }
}

/// One public connection, as a byte stream: the plaintext HTTP of a
/// `terminated` host, the plaintext of a `tls_offload` host, or the raw TLS of
/// a `passthrough` host.
pub struct InternalConnection {
    stream: DuplexStream,
    hostname: String,
    peer: SocketAddr,
    tls_mode: TlsMode,
}

impl InternalConnection {
    /// The SNI of the public connection.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The address of the public client.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub fn tls_mode(&self) -> TlsMode {
        self.tls_mode
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
                let peer = connection.peer;
                (connection, peer)
            }
            // axum retries an accept forever: after shutdown, wait for good
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
    async fn test_a_connection_reaches_the_listener_with_its_peer() {
        let internal = Internal::default();
        let mut listener = internal.listen("admin").unwrap();

        let mut ours = internal
            .connect("admin", "admin.example.com", peer(), TlsMode::Terminated)
            .await
            .unwrap();
        let mut theirs = listener.accept().await.unwrap();
        ours.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        theirs.read_exact(&mut got).await.unwrap();

        assert_eq!(&got, b"ping");
        assert_eq!(theirs.hostname(), "admin.example.com");
        assert_eq!(theirs.peer_addr(), peer());
        assert_eq!(theirs.tls_mode(), TlsMode::Terminated);
    }

    #[tokio::test]
    async fn test_a_name_is_taken_until_its_listener_drops() {
        let internal = Internal::default();
        let listener = internal.listen("admin").unwrap();

        assert!(matches!(
            internal.listen("admin"),
            Err(ServerError::InternalListenerTaken(_))
        ));
        drop(listener);
        assert!(internal.listen("admin").is_ok());
    }

    #[tokio::test]
    async fn test_an_unknown_name_gets_no_connection() {
        let internal = Internal::default();

        let stream = internal
            .connect("admin", "admin.example.com", peer(), TlsMode::Terminated)
            .await;

        assert!(stream.is_none());
    }

    #[tokio::test]
    async fn test_close_ends_accept() {
        let internal = Internal::default();
        let mut listener = internal.listen("admin").unwrap();

        internal.close();

        assert!(listener.accept().await.is_none());
    }
}
