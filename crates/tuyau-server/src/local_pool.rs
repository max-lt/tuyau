//! Keep-alive h1 connections to the local upstreams of terminated hosts. The
//! requests of all public connections share them, so a request does not open
//! a TCP connection to its backend.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::{Client, Error};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::UnixStream;

use crate::public::UPSTREAM_CONNECT_TIMEOUT;
use crate::routes::UpstreamTarget;

/// Shorter than the 5 s keep-alive of Node servers: the pool closes an idle
/// connection before the backend does, or a request can meet a closed one.
const IDLE_TIMEOUT: Duration = Duration::from_secs(4);

const MAX_IDLE_PER_BACKEND: usize = 64;

/// The pooled clients of one public listener.
#[derive(Clone)]
pub(crate) struct LocalPool {
    tcp: Client<HttpConnector, Incoming>,
    unix: Client<UnixConnector, Incoming>,
}

impl LocalPool {
    pub(crate) fn new() -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(IDLE_TIMEOUT)
            .pool_max_idle_per_host(MAX_IDLE_PER_BACKEND)
            // The request already has the Host of the client
            .set_host(false);

        let mut tcp = HttpConnector::new();
        tcp.set_nodelay(true);
        tcp.set_connect_timeout(Some(UPSTREAM_CONNECT_TIMEOUT));

        Self {
            tcp: builder.build(tcp),
            unix: builder.build(UnixConnector),
        }
    }

    /// Sends `req`, an origin-form h1 request with its Host, to `target`.
    pub(crate) async fn send(
        &self,
        target: &UpstreamTarget,
        mut req: Request<Incoming>,
    ) -> Result<Response<Incoming>, Error> {
        // The client needs an absolute URI; it sends the origin form. Its
        // authority keys the pool and names the target for the connector.
        let authority = match target {
            UpstreamTarget::Tcp(addr) => addr.to_string(),
            UpstreamTarget::Unix(path) => hex_encode(path.as_os_str().as_encoded_bytes()),
        };
        let path = req.uri().path_and_query().map_or("/", |path| path.as_str());
        *req.uri_mut() = format!("http://{authority}{path}")
            .parse()
            .expect("an address or a hex label is a URI authority");

        match target {
            UpstreamTarget::Tcp(_) => self.tcp.request(req).await,
            UpstreamTarget::Unix(_) => self.unix.request(req).await,
        }
    }
}

/// Connects to the Unix socket whose path is the hex host of the URI.
#[derive(Clone)]
struct UnixConnector;

impl tower_service::Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            let path = uri
                .host()
                .and_then(hex_decode)
                .map(|bytes| PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
                .ok_or_else(|| std::io::Error::other(format!("not a socket URI: {uri}")))?;

            let stream = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, UnixStream::connect(&path))
                .await
                .map_err(|_| {
                    std::io::Error::other(format!("connect timeout: {}", path.display()))
                })??;

            Ok(TokioIo::new(stream))
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }

    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_path_survives_the_uri_authority() {
        let path = "/run/app/http.sock";
        let host = hex_encode(path.as_bytes());
        let uri: Uri = format!("http://{host}/x").parse().unwrap();

        assert_eq!(hex_decode(uri.host().unwrap()).unwrap(), path.as_bytes());
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
