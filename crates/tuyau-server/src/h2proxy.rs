//! HTTP/2 termination for the public listener.
//!
//! A terminated connection that negotiates ALPN `h2` can't be byte-piped: the
//! browser speaks HTTP/2 framing, but the backend (over the tunnel, or a local
//! upstream) speaks HTTP/1.1. So we run a hyper h2 server facing the browser
//! and, per request, do an h1 client round-trip to the backend over a fresh
//! stream.
//!
//! This is the one place the server stops being a transparent byte-pipe and
//! becomes a real HTTP reverse proxy — only for h2 connections. h1 (and any
//! non-HTTP) traffic still flows through the byte-pipe in `public.rs`.
//!
//! The win: browsers get h2 (one connection, multiplexing, HPACK) while the
//! backend stays h1, with no end-to-end ALPN contract to honour. h2's request
//! multiplexing maps onto one tunnel stream / backend connection per request —
//! the same shape the byte-pipe uses, just per-request instead of per-connection.
//!
//! WebSockets: browsers carry WebSocket over h2 via RFC 8441 Extended CONNECT
//! (`:method=CONNECT`, `:protocol=websocket`). We advertise support, then
//! translate each such stream into an HTTP/1.1 `Upgrade: websocket` handshake to
//! the backend and splice the two byte streams.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::ext::Protocol;
use hyper::header::{
    CONNECTION, HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};

use crate::public::{connect_tcp, connect_unix, open_tunnel_stream};
use crate::routes::{Route, RoutingTable, UpstreamTarget};

/// One concrete response-body type for the h2 server: either the backend's
/// streamed h1 response or a small in-memory page, boxed to unify them.
type ProxyBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Cap concurrent h2 streams per connection. Each stream maps to one tunnel
/// stream / backend connection, and a whole h2 connection counts as just one
/// permit against the global / per-IP connection caps — so without this a single
/// connection could fan out unboundedly. 256 is generous for a browser (which
/// opens far fewer) while bounding abuse.
const MAX_CONCURRENT_STREAMS: u32 = 256;
/// Bound request header size (HPACK-decoded) so a peer can't force large
/// allocations. 64 KiB is well above any real browser request.
const MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
/// h2 keep-alive: PING idle peers and reap them if they don't answer, so dead
/// connections don't pin a permit forever.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Bound the h1 handshake to the backend so a hung backend can't stall a stream
/// during setup. The request/response themselves are not timed out — responses
/// may legitimately stream for a long time (SSE, downloads).
const BACKEND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Fixed `Sec-WebSocket-Key` for the synthesized h1 handshake to the backend.
/// The real WebSocket security handshake already happened between the browser
/// and us (over h2/TLS); the h1 leg is an internal, dedicated, single-use
/// connection, and the backend only echoes a derived `Sec-WebSocket-Accept` we
/// don't need to verify — so a constant key (16 zero bytes, base64) is fine and
/// saves a randomness/base64 dependency.
const WS_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

/// Serve a terminated, h2-negotiated TLS stream as an HTTP/2 reverse proxy.
/// Each request is bridged to the live backend over h1; the route is looked up
/// per request so reconnects/rebalances take effect mid-connection.
pub(crate) async fn serve_h2<S>(
    tls_stream: S,
    routes: RoutingTable,
    sni: String,
    peer: SocketAddr,
    error_502: Arc<str>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(tls_stream);
    let service = service_fn(move |req| {
        proxy(req, routes.clone(), sni.clone(), peer, error_502.clone())
    });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new()) // required by keep-alive below
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
    // Advertise RFC 8441 so browsers tunnel WebSocket over this h2 connection
    // (Extended CONNECT) instead of failing; we translate it to an h1 upgrade.
    builder.enable_connect_protocol();
    if let Err(e) = builder.serve_connection(io, service).await {
        tracing::debug!(peer = %peer, error = %e, "h2 connection ended with error");
    }
}

/// Route and proxy a single h2 request to the live backend as h1. Always
/// resolves to a `Response` (a 502 page on any backend failure) so the h2
/// connection stays usable for sibling streams.
async fn proxy(
    req: Request<Incoming>,
    routes: RoutingTable,
    sni: String,
    peer: SocketAddr,
    error_502: Arc<str>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    match routes.lookup(&sni) {
        Some(Route::Tunnel(entry)) => {
            let Some((send, recv)) = open_tunnel_stream(&entry, &sni, peer).await else {
                return Ok(bad_gateway(&error_502));
            };
            // RecvStream is the read half, SendStream the write half; join them
            // into one duplex for the h1 client.
            let io = tokio::io::join(recv, send);
            Ok(serve_request(io, req, &sni, peer, &error_502).await)
        }
        Some(Route::Local { target, .. }) => match target {
            UpstreamTarget::Tcp(addr) => match connect_tcp(addr, &sni, peer).await {
                Some(up) => Ok(serve_request(up, req, &sni, peer, &error_502).await),
                None => Ok(bad_gateway(&error_502)),
            },
            UpstreamTarget::Unix(path) => match connect_unix(&path, &sni, peer).await {
                Some(up) => Ok(serve_request(up, req, &sni, peer, &error_502).await),
                None => Ok(bad_gateway(&error_502)),
            },
        },
        None => {
            tracing::info!(peer = %peer, sni = %sni, "terminated h2, no live route — serving 502");
            Ok(bad_gateway(&error_502))
        }
    }
}

/// Dispatch a single request over an established backend stream: WebSocket
/// (Extended CONNECT) gets the h1 upgrade bridge, everything else a plain h1
/// round-trip.
async fn serve_request<S>(
    io: S,
    req: Request<Incoming>,
    sni: &str,
    peer: SocketAddr,
    error_502: &str,
) -> Response<ProxyBody>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if is_websocket_connect(&req) {
        ws_bridge(io, req, sni, peer, error_502).await
    } else if req.method() == Method::CONNECT {
        // A non-WebSocket CONNECT to an origin isn't something we proxy.
        tracing::warn!(peer = %peer, sni = %sni, "unsupported CONNECT (not websocket)");
        bad_gateway(error_502)
    } else {
        h1_roundtrip(io, req, sni, peer, error_502).await
    }
}

/// True for an RFC 8441 WebSocket-over-h2 request (`CONNECT` + `:protocol`).
fn is_websocket_connect(req: &Request<Incoming>) -> bool {
    req.method() == Method::CONNECT
        && req
            .extensions()
            .get::<Protocol>()
            .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"))
}

/// Drive an h1 client handshake over `io`, forward `req`, and return the
/// backend's response. A 502 page on any error.
async fn h1_roundtrip<S>(
    io: S,
    req: Request<Incoming>,
    sni: &str,
    peer: SocketAddr,
    error_502: &str,
) -> Response<ProxyBody>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(io));
    let (mut sender, conn) = match tokio::time::timeout(BACKEND_HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "backend h1 handshake failed");
            return bad_gateway(error_502);
        }
        Err(_) => {
            tracing::warn!(peer = %peer, sni = %sni, "backend h1 handshake timed out");
            return bad_gateway(error_502);
        }
    };
    // The connection task drives the byte plumbing; the sender issues requests.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "backend h1 connection ended with error");
        }
    });
    match sender.send_request(req).await {
        Ok(resp) => resp.map(|b| b.boxed()),
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "backend h1 request failed");
            bad_gateway(error_502)
        }
    }
}

/// Translate a WebSocket-over-h2 (Extended CONNECT) stream into an HTTP/1.1
/// `Upgrade: websocket` handshake to the backend, then splice the two byte
/// streams. Returns the `200` that completes the h2 side (browsers expect 200,
/// not 101, for RFC 8441); the splice runs in a spawned task once both ends are
/// upgraded.
async fn ws_bridge<S>(
    backend: S,
    mut req: Request<Incoming>,
    sni: &str,
    peer: SocketAddr,
    error_502: &str,
) -> Response<ProxyBody>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Build the h1 upgrade request from the h2 CONNECT. RFC 8441 omits
    // Sec-WebSocket-Key on the h2 side, so we synthesize one for the h1 leg.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| sni.to_string());
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();

    let mut bld = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, authority)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(SEC_WEBSOCKET_KEY, WS_KEY);
    // Carry the browser's subprotocol offer through to the backend, and echo the
    // backend's choice back below. We deliberately do NOT forward
    // Sec-WebSocket-Extensions: the browser negotiated the WS handshake with us
    // (over h2), and we don't relay the backend's extension response, so letting
    // the backend negotiate permessage-deflate would desync the two ends. No
    // extension = always correct.
    if let Some(v) = req.headers().get(SEC_WEBSOCKET_PROTOCOL) {
        bld = bld.header(SEC_WEBSOCKET_PROTOCOL, v);
    }
    let breq = match bld.body(Empty::<Bytes>::new()) {
        Ok(r) => r,
        Err(_) => return bad_gateway(error_502),
    };

    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(backend));
    let (mut sender, conn) = match tokio::time::timeout(BACKEND_HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "backend ws handshake failed");
            return bad_gateway(error_502);
        }
        Err(_) => {
            tracing::warn!(peer = %peer, sni = %sni, "backend ws handshake timed out");
            return bad_gateway(error_502);
        }
    };
    // `.with_upgrades()` keeps the connection alive past the 101 so the upgraded
    // byte stream stays usable.
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let bresp = match sender.send_request(breq).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "backend ws request failed");
            return bad_gateway(error_502);
        }
    };
    if bresp.status() != StatusCode::SWITCHING_PROTOCOLS {
        tracing::warn!(peer = %peer, sni = %sni, status = %bresp.status(), "backend did not upgrade websocket");
        return bad_gateway(error_502);
    }
    let subproto = bresp.headers().get(SEC_WEBSOCKET_PROTOCOL).cloned();

    let backend_up = match hyper::upgrade::on(bresp).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(peer = %peer, sni = %sni, error = %e, "backend ws upgrade failed");
            return bad_gateway(error_502);
        }
    };

    // Capture the browser-side (h2) upgrade and splice once it resolves — which
    // happens after we return the 200 below and hyper flushes it.
    let client_up = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match client_up.await {
            Ok(client_up) => {
                let mut a = TokioIo::new(client_up);
                let mut b = TokioIo::new(backend_up);
                if let Err(e) = copy_bidirectional(&mut a, &mut b).await {
                    tracing::debug!(error = %e, "websocket splice ended with error");
                }
            }
            Err(e) => tracing::debug!(error = %e, "h2 websocket upgrade failed"),
        }
    });

    let mut rb = Response::builder().status(StatusCode::OK);
    if let Some(sp) = subproto {
        rb = rb.header(SEC_WEBSOCKET_PROTOCOL, sp);
    }
    rb.body(empty_body())
        .unwrap_or_else(|_| bad_gateway(error_502))
}

/// An empty boxed body for the WebSocket `200` response.
fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

/// A 502 response carrying the (branded) error page, mirroring the byte-pipe's
/// `write_502` so h1 and h2 visitors see the same thing.
fn bad_gateway(body: &str) -> Response<ProxyBody> {
    let full = Full::new(Bytes::from(body.to_owned()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("content-type", "text/html; charset=utf-8")
        .body(full)
        .expect("static 502 response is always valid")
}
