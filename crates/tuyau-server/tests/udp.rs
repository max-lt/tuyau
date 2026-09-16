//! Public UDP listener, server side: per-port routing to a static local
//! upstream, plus the properties that make a UDP proxy safe to expose —
//! sessions that never change their return address, and a bounded table.
//!
//! These drive the `[[udp]]` + `local_addr` shape (no tunnel involved); the
//! tunnel path is covered end-to-end in `tuyau-client`'s `udp_dispatch.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::net::UdpSocket;

use tuyau_server::{ServerConfig, TunnelServer, UdpEntry};

/// Long enough to be a real failure on a loopback round trip, short enough that
/// "nothing came back" tests don't drag.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
const SILENCE_WINDOW: Duration = Duration::from_millis(400);

fn config(dir: &TempDir, udp: Vec<UdpEntry>) -> ServerConfig {
    ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: None,
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![],
        max_public_connections: None,
        error_502_file: None,
        udp,
    }
}

fn udp_route(name: &str, local: SocketAddr) -> UdpEntry {
    UdpEntry {
        name: name.into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        client: None,
        local_addr: Some(local),
        idle_timeout_secs: None,
        max_sessions: None,
        amplification_factor: None,
    }
}

/// A request padded past the anti-amplification budget, so a reply larger than
/// the request still fits. QUIC pads its handshake for exactly this reason.
fn padded(tag: u8) -> Vec<u8> {
    vec![tag; 256]
}

/// Plain UDP echo service: replies to whoever sent each packet.
async fn spawn_echo() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Echo service that answers with *its view of the sender's address*. Lets a
/// test see how many distinct local sockets tuyau opened toward it.
async fn spawn_source_reporter() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((_, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(peer.to_string().as_bytes(), peer).await;
        }
    });
    addr
}

/// Service that replies to the FIRST peer it ever saw, whatever the packet's
/// actual source — a deliberately "redirectable" backend. If tuyau ever routed
/// a reply by anything other than the session it arrived on, this would leak
/// one peer's traffic to another.
async fn spawn_sticky_first_peer() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut first: Option<SocketAddr> = None;
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let target = *first.get_or_insert(peer);
            let _ = sock.send_to(&buf[..n], target).await;
        }
    });
    addr
}

async fn public_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

/// Send `msg` and wait for a reply, or fail with `what` as context.
async fn round_trip(sock: &UdpSocket, to: SocketAddr, msg: &[u8], what: &str) -> Vec<u8> {
    sock.send_to(msg, to).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(REPLY_TIMEOUT, sock.recv(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{what}: no reply within {REPLY_TIMEOUT:?}"))
        .unwrap();
    buf.truncate(n);
    buf
}

/// Assert nothing arrives on `sock` for a short window.
async fn expect_silence(sock: &UdpSocket, what: &str) {
    let mut buf = vec![0u8; 2048];
    let got = tokio::time::timeout(SILENCE_WINDOW, sock.recv(&mut buf)).await;
    if let Ok(Ok(n)) = got {
        panic!(
            "{what}: unexpectedly received {n} bytes: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
    }
}

#[tokio::test]
async fn udp_route_forwards_to_a_local_upstream_and_back() {
    let echo = spawn_echo().await;
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start(config(&dir, vec![udp_route("echo", echo)]))
        .await
        .unwrap();
    let public = server.udp_local_addr("echo").expect("route is bound");

    let client = public_socket().await;
    assert_eq!(
        round_trip(&client, public, b"ping", "first packet").await,
        b"ping"
    );
    // A second packet reuses the session rather than opening a new one.
    assert_eq!(
        round_trip(&client, public, b"pong", "second packet").await,
        b"pong"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn a_new_source_address_gets_its_own_session_and_local_socket() {
    // The roaming primitive: tuyau never repoints a session, it opens a new one.
    // The local service therefore sees a distinct source per public peer —
    // which is exactly what lets WireGuard authenticate a roamed peer and move
    // its endpoint itself.
    let reporter = spawn_source_reporter().await;
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start(config(&dir, vec![udp_route("wg", reporter)]))
        .await
        .unwrap();
    let public = server.udp_local_addr("wg").expect("route is bound");

    let first = public_socket().await;
    let seen_a = round_trip(&first, public, &padded(b'a'), "first peer").await;

    // Same host, new source port — what a NAT rebinding looks like from here.
    let second = public_socket().await;
    let seen_b = round_trip(&second, public, &padded(b'b'), "rebound peer").await;

    assert_ne!(
        seen_a, seen_b,
        "each session must reach the backend from its own local socket"
    );

    // The original session is untouched by the new one: it still works, and it
    // still comes from the same local socket as before.
    let seen_a_again =
        round_trip(&first, public, &padded(b'a'), "first peer after rebinding").await;
    assert_eq!(
        seen_a, seen_a_again,
        "an existing session must keep its local socket"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn a_packet_from_another_address_cannot_redirect_an_existing_session() {
    // The backend here is deliberately hostile to the property under test: it
    // replies to the first peer it saw, no matter who actually sent the packet.
    // Even so, a reply can only reach the public peer whose session carried it,
    // because a session's return address is fixed when it is created and no
    // packet from anywhere can change it.
    let sticky = spawn_sticky_first_peer().await;
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start(config(&dir, vec![udp_route("wg", sticky)]))
        .await
        .unwrap();
    let public = server.udp_local_addr("wg").expect("route is bound");

    let victim = public_socket().await;
    assert_eq!(
        round_trip(&victim, public, b"victim-1", "victim establishes a session").await,
        b"victim-1"
    );

    // A second address sends a packet the backend answers *toward the victim's
    // local socket*. That reply belongs to the victim's session, so it goes to
    // the victim — never to the sender that provoked it.
    let attacker = public_socket().await;
    attacker.send_to(b"attacker", public).await.unwrap();
    expect_silence(
        &attacker,
        "attacker must not receive the victim's session traffic",
    )
    .await;

    // And the victim's session is intact: still live, still answering at the
    // victim's own address.
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(REPLY_TIMEOUT, victim.recv(&mut buf))
        .await
        .expect("the provoked reply is delivered to the session owner")
        .unwrap();
    assert_eq!(&buf[..n], b"attacker");
    assert_eq!(
        round_trip(&victim, public, b"victim-2", "victim after the spoof").await,
        b"victim-2"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn an_unvalidated_peer_cannot_be_used_to_amplify() {
    // A tiny request that provokes a much larger reply is the reflection-attack
    // shape. Until the peer proves it is really there, tuyau will not send it.
    let reporter = spawn_source_reporter().await;
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start(config(&dir, vec![udp_route("dns-ish", reporter)]))
        .await
        .unwrap();
    let public = server.udp_local_addr("dns-ish").expect("route is bound");

    // 1 byte in, ~20 bytes of address string back: over the 3x default.
    let sock = public_socket().await;
    sock.send_to(b"q", public).await.unwrap();
    expect_silence(
        &sock,
        "an amplifying reply to an unvalidated peer must be dropped",
    )
    .await;

    // The same route with the same backend works once the request carries
    // enough bytes to pay for its own answer.
    let ok = round_trip(&sock, public, &padded(b'q'), "padded request").await;
    assert!(!ok.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn a_route_can_opt_into_a_higher_amplification_factor() {
    // Asymmetric request/response protocols (DNS) need the budget raised. It is
    // a deliberate, per-route decision — the port can then amplify that much.
    let reporter = spawn_source_reporter().await;
    let dir = TempDir::new().unwrap();
    let mut route = udp_route("dns-ish", reporter);
    route.amplification_factor = Some(100);
    let server = TunnelServer::start(config(&dir, vec![route]))
        .await
        .unwrap();
    let public = server.udp_local_addr("dns-ish").expect("route is bound");

    let sock = public_socket().await;
    let reply = round_trip(&sock, public, b"q", "tiny request on a raised budget").await;
    assert!(reply.len() > 1, "the larger reply is delivered: {reply:?}");

    server.shutdown().await;
}

#[tokio::test]
async fn the_session_table_is_bounded() {
    // Source addresses are forgeable, so the table must have a ceiling: past it
    // new peers are dropped rather than allocated for.
    let echo = spawn_echo().await;
    let dir = TempDir::new().unwrap();
    let mut route = udp_route("echo", echo);
    route.max_sessions = Some(1);
    let server = TunnelServer::start(config(&dir, vec![route]))
        .await
        .unwrap();
    let public = server.udp_local_addr("echo").expect("route is bound");

    let first = public_socket().await;
    assert_eq!(
        round_trip(&first, public, b"one", "session under the cap").await,
        b"one"
    );

    let second = public_socket().await;
    second.send_to(b"two", public).await.unwrap();
    expect_silence(&second, "a peer past the session cap must be dropped").await;

    // The peer that holds the one slot is unaffected by the flood.
    assert_eq!(
        round_trip(&first, public, b"still", "capped-out peer").await,
        b"still"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn several_udp_routes_bind_independently() {
    // Per-port routing: each `[[udp]]` entry is its own socket and its own
    // target, with no payload inspection and nothing shared between them.
    let a = spawn_echo().await;
    let b = spawn_source_reporter().await;
    let dir = TempDir::new().unwrap();
    let server = TunnelServer::start(config(&dir, vec![udp_route("a", a), udp_route("b", b)]))
        .await
        .unwrap();
    let pub_a = server.udp_local_addr("a").unwrap();
    let pub_b = server.udp_local_addr("b").unwrap();
    assert_ne!(pub_a, pub_b);
    assert!(server.udp_local_addr("nope").is_none());

    let sock = public_socket().await;
    let msg = padded(b'x');
    assert_eq!(round_trip(&sock, pub_a, &msg, "route a").await, msg);
    // Route b answers with the source it saw, so it is plainly the other target.
    let via_b = round_trip(&sock, pub_b, &msg, "route b").await;
    assert_ne!(via_b, msg);

    assert!(server.healthy());
    server.shutdown().await;
}

#[tokio::test]
async fn a_udp_route_with_no_live_tunnel_drops_silently() {
    // A tunnel route whose client has never connected: there is nothing to
    // forward to, and UDP has no "no backend" to answer with. Anything else
    // would make the port an amplifier.
    let dir = TempDir::new().unwrap();
    let mut cfg = config(&dir, vec![]);
    cfg.clients = vec![tuyau_server::ClientEntry {
        name: "service-a".into(),
        token: [7u8; 32],
        balance: Default::default(),
    }];
    cfg.udp = vec![UdpEntry {
        name: "wg".into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        client: Some("service-a".into()),
        local_addr: None,
        idle_timeout_secs: None,
        max_sessions: None,
        amplification_factor: None,
    }];
    let server = TunnelServer::start(cfg).await.unwrap();
    let public = server.udp_local_addr("wg").expect("route is bound");

    assert!(
        server.active_udp_routes().is_empty(),
        "no tunnel is connected"
    );

    let sock = public_socket().await;
    sock.send_to(b"anyone there?", public).await.unwrap();
    expect_silence(&sock, "an unrouted udp port must stay silent").await;

    assert!(
        server.healthy(),
        "dropping traffic must not kill the listener"
    );
    server.shutdown().await;
}
