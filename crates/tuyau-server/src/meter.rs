//! Counts the bytes of a public connection, for its close log.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The bytes that a public connection read from its client and wrote to it.
#[derive(Debug, Default)]
pub(crate) struct Meter {
    read: AtomicU64,
    written: AtomicU64,
}

impl Meter {
    pub(crate) fn read(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    pub(crate) fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

/// A stream that adds its reads and writes to a [`Meter`].
pub(crate) struct Metered<S> {
    inner: S,
    meter: Arc<Meter>,
}

impl<S> Metered<S> {
    pub(crate) fn new(inner: S, meter: Arc<Meter>) -> Self {
        Self { inner, meter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = poll {
            let count = (buf.filled().len() - before) as u64;
            self.meter.read.fetch_add(count, Ordering::Relaxed);
        }

        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(count)) = poll {
            self.meter
                .written
                .fetch_add(count as u64, Ordering::Relaxed);
        }

        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);

        if let Poll::Ready(Ok(count)) = poll {
            self.meter
                .written
                .fetch_add(count as u64, Ordering::Relaxed);
        }

        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_meter_counts_reads_and_writes() {
        let (client, server) = tokio::io::duplex(64);
        let meter = Arc::new(Meter::default());
        let mut metered = Metered::new(server, meter.clone());
        let mut client = client;

        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        metered.read_exact(&mut buf).await.unwrap();
        metered.write_all(b"hi").await.unwrap();

        assert_eq!((meter.read(), meter.written()), (5, 2));
    }
}
