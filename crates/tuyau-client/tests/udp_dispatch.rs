//! End-to-end UDP: a public UDP socket → the server's `[[udp]]` listener →
//! QUIC datagrams over a real tunnel → `tuyau-client` → a local UDP service,
//! and all the way back.
//!
//! The roaming test is the one that matters most. It is shaped like WireGuard:
//! the local service keeps a single socket and answers whichever source it most
//! recently accepted a packet from — which is what WireGuard does when it
//! authenticates a packet from a roamed peer and moves that peer's endpoint.
//! tuyau never repoints a session itself; it just gives each public source
//! address its own session and its own local socket, and lets the service's own
//! cryptography decide. That is what makes a mid-session address change work
//! while a spoofed packet gets nowhere.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::net::UdpSocket;

use tuyau_client::{ClientConfig, TunnelClient, UdpIngressRule};
use tuyau_server::{ClientEntry, ServerConfig, TunnelServer, UdpEntry};

const TOKEN: [u8; 32] = [0x42; 32];
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const SILENCE_WINDOW: Duration = Duration::from_millis(500);

/// A request padded past the anti-amplification budget, so a reply at least as
/// large as the request is always affordable.
fn padded(tag: &[u8]) -> Vec<u8> {
    let mut v = tag.to_vec();
    v.resize(256, b'.');
    v
}

async fn spin_up(udp: Vec<UdpEntry>) -> (TunnelServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_listen_addr: None,
        tunnel_cert_dir: Some(dir.path().to_path_buf()),
        clients: vec![ClientEntry {
            name: "service-a".into(),
            token: TOKEN,
            balance: Default::default(),
        }],
        hostnames: vec![],
        acme: None,
        tls_cert_file: None,
        tls_key_file: None,
        upstreams: vec![],
        max_public_connections: None,
        error_502_file: None,
        udp,
    };
    let server = TunnelServer::start(cfg).await.unwrap();
    (server, dir)
}

fn tunnel_route(name: &str) -> UdpEntry {
    UdpEntry {
        name: name.into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        client: Some("service-a".into()),
        local_addr: None,
        idle_timeout_secs: None,
        max_sessions: None,
        amplification_factor: None,
    }
}

/// A connected tunnel plus its background `serve()` task. Holding it keeps the
/// tunnel alive; `shutdown()` tears both down deterministically.
struct Tunnel {
    client: Arc<TunnelClient>,
    serve: tokio::task::JoinHandle<()>,
}

impl Tunnel {
    async fn shutdown(self) {
        self.serve.abort();
        let _ = self.serve.await;
        Arc::try_unwrap(self.client)
            .expect("the serve task is the only other holder and it has been joined")
            .shutdown()
            .await;
    }
}

/// Connect a tunnel client with the given UDP ingress rules and start serving.
async fn connect_and_serve(server: &TunnelServer, udp_ingress: Vec<UdpIngressRule>) -> Tunnel {
    let cfg = ClientConfig {
        server_addr: format!("127.0.0.1:{}", server.local_addr().unwrap().port()),
        server_cert_fingerprint_sha256: server.cert_fingerprint(),
        token: TOKEN,
        client_name: "service-a".into(),
        ingress: vec![],
        udp_ingress,
    };
    let client = Arc::new(TunnelClient::connect(cfg).await.unwrap());
    let serving = Arc::clone(&client);
    let serve = tokio::spawn(async move {
        let _ = serving.serve().await;
    });
    Tunnel { client, serve }
}

fn ingress(name: &str, local: SocketAddr) -> Vec<UdpIngressRule> {
    vec![UdpIngressRule {
        name: name.into(),
        local_addr: local.to_string(),
    }]
}

/// Plain UDP echo service: replies to whoever sent each packet.
async fn spawn_echo() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// WireGuard-shaped service: one socket, and every reply goes to the source of
/// the most recently *accepted* packet — i.e. it moves the peer's endpoint the
/// way WireGuard does once it has authenticated a roamed packet.
async fn spawn_roaming_peer_service() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        // The peer's endpoint, as WireGuard tracks it: replaced by the source
        // of every packet that authenticates, and replied to from then on.
        let mut endpoint: SocketAddr;
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            endpoint = peer; // "authenticated; update the peer endpoint"
            let _ = sock.send_to(&buf[..n], endpoint).await;
        }
    });
    addr
}

async fn public_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn round_trip(sock: &UdpSocket, to: SocketAddr, msg: &[u8], what: &str) -> Vec<u8> {
    sock.send_to(msg, to).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(REPLY_TIMEOUT, sock.recv(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{what}: no reply within {REPLY_TIMEOUT:?}"))
        .unwrap();
    buf.truncate(n);
    buf
}

async fn expect_silence(sock: &UdpSocket, what: &str) {
    let mut buf = vec![0u8; 65535];
    if let Ok(Ok(n)) = tokio::time::timeout(SILENCE_WINDOW, sock.recv(&mut buf)).await {
        panic!("{what}: unexpectedly received {n} bytes");
    }
}

#[tokio::test]
async fn udp_round_trips_over_the_tunnel() {
    let echo = spawn_echo().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg")]).await;
    let public = server.udp_local_addr("wg").expect("route is bound");
    let _client = connect_and_serve(&server, ingress("wg", echo)).await;

    // The route is only live once the owning tunnel is connected.
    assert_eq!(server.active_udp_routes(), vec!["wg".to_string()]);

    let sock = public_socket().await;
    let msg = padded(b"hello-udp");
    assert_eq!(round_trip(&sock, public, &msg, "first datagram").await, msg);

    // A second datagram reuses the session on both ends.
    let msg2 = padded(b"second");
    assert_eq!(
        round_trip(&sock, public, &msg2, "second datagram").await,
        msg2
    );

    server.shutdown().await;
}

#[tokio::test]
async fn a_session_survives_the_public_source_address_changing() {
    // Roaming: NAT rebinding / wifi → 4G. The public peer reappears from a new
    // source port mid-session, so tuyau opens a new session with a new local
    // socket; the service authenticates the packet, moves the peer's endpoint,
    // and replies flow back to the new public address.
    let service = spawn_roaming_peer_service().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg")]).await;
    let public = server.udp_local_addr("wg").expect("route is bound");
    let _client = connect_and_serve(&server, ingress("wg", service)).await;

    let before = public_socket().await;
    let msg = padded(b"before-roam");
    assert_eq!(
        round_trip(&before, public, &msg, "before roaming").await,
        msg
    );

    // Same peer, new source address — nothing tells tuyau these are related,
    // and it must not try to guess.
    let after = public_socket().await;
    let roamed = padded(b"after-roam");
    assert_eq!(
        round_trip(&after, public, &roamed, "after roaming").await,
        roamed,
        "traffic must keep flowing from the new source address"
    );

    // And the reply went to the roamed address, not the old one — the service
    // moved its endpoint, exactly as it would with no proxy in the path.
    expect_silence(
        &before,
        "the abandoned address must not receive the roamed session",
    )
    .await;

    server.shutdown().await;
}

#[tokio::test]
async fn a_spoofed_source_cannot_take_over_a_live_session() {
    // The same mechanism, viewed as an attack: a third address sending into a
    // live session gets a session of its own, never the victim's. The victim's
    // return address is fixed for the session's whole life.
    let echo = spawn_echo().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg")]).await;
    let public = server.udp_local_addr("wg").expect("route is bound");
    let _client = connect_and_serve(&server, ingress("wg", echo)).await;

    let victim = public_socket().await;
    let v1 = padded(b"victim-1");
    assert_eq!(
        round_trip(&victim, public, &v1, "victim establishes").await,
        v1
    );

    // An attacker replays what it could have observed on the wire. With a
    // proxy that matched on in-packet identifiers this is where the session
    // would be hijacked.
    let attacker = public_socket().await;
    attacker.send_to(&v1, public).await.unwrap();

    // The echo answers the attacker's own session — the attacker gets its own
    // packet back and nothing else. What matters is what it did NOT get: any
    // control over where the victim's traffic goes.
    let mut buf = vec![0u8; 65535];
    let _ = tokio::time::timeout(SILENCE_WINDOW, attacker.recv(&mut buf)).await;

    let v2 = padded(b"victim-2");
    assert_eq!(
        round_trip(&victim, public, &v2, "victim after the spoof").await,
        v2,
        "the victim's session must be untouched"
    );
    expect_silence(
        &attacker,
        "the attacker must not receive the victim's traffic",
    )
    .await;

    server.shutdown().await;
}

#[tokio::test]
async fn a_datagram_too_large_for_the_tunnel_is_dropped_without_breaking_the_session() {
    // Datagrams that don't fit after encapsulation are dropped, not fragmented.
    // The session must survive that — the next packet still round-trips.
    let echo = spawn_echo().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg")]).await;
    let public = server.udp_local_addr("wg").expect("route is bound");
    let _client = connect_and_serve(&server, ingress("wg", echo)).await;

    let sock = public_socket().await;
    let small = padded(b"small");
    assert_eq!(round_trip(&sock, public, &small, "warm-up").await, small);

    // Far beyond any path MTU.
    sock.send_to(&vec![0xAB; 60_000], public).await.unwrap();
    expect_silence(
        &sock,
        "an oversized datagram must be dropped, not fragmented",
    )
    .await;

    let after = padded(b"after-oversize");
    assert_eq!(
        round_trip(&sock, public, &after, "after the oversized drop").await,
        after,
        "the session must survive an oversized packet"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn a_route_with_no_matching_udp_ingress_is_dropped_by_the_client() {
    // The server routes by port and the client maps route names to local
    // services. A client with no rule for the route drops the datagram and
    // keeps serving, rather than failing the tunnel.
    let echo = spawn_echo().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg"), tunnel_route("other")]).await;
    let wg_public = server.udp_local_addr("wg").expect("route is bound");
    let other_public = server.udp_local_addr("other").expect("route is bound");
    // Only "wg" is mapped locally.
    let _client = connect_and_serve(&server, ingress("wg", echo)).await;

    let sock = public_socket().await;
    sock.send_to(&padded(b"unmapped"), other_public)
        .await
        .unwrap();
    expect_silence(&sock, "an unmapped route must be dropped").await;

    // The mapped route is unaffected.
    let msg = padded(b"mapped");
    assert_eq!(
        round_trip(&sock, wg_public, &msg, "mapped route").await,
        msg
    );

    server.shutdown().await;
}

#[tokio::test]
async fn udp_sessions_die_with_their_tunnel_and_come_back_with_it() {
    // A tunnel going away leaves its sessions unusable; a reconnecting client
    // gets fresh ones. Datagrams in between are dropped, not queued.
    let echo = spawn_echo().await;
    let (server, _dir) = spin_up(vec![tunnel_route("wg")]).await;
    let public = server.udp_local_addr("wg").expect("route is bound");

    let client = connect_and_serve(&server, ingress("wg", echo)).await;
    let sock = public_socket().await;
    let msg = padded(b"before-drop");
    assert_eq!(
        round_trip(&sock, public, &msg, "before the tunnel drops").await,
        msg
    );

    // Drop the tunnel and wait for the server to notice.
    client.shutdown().await;
    for _ in 0..50 {
        if server.active_udp_routes().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        server.active_udp_routes().is_empty(),
        "the route should be down"
    );

    sock.send_to(&padded(b"orphan"), public).await.unwrap();
    expect_silence(&sock, "a route with no live tunnel must stay silent").await;

    // Reconnect: the route comes back and new sessions work.
    let _client = connect_and_serve(&server, ingress("wg", echo)).await;
    let again = padded(b"after-reconnect");
    let sock2 = public_socket().await;
    assert_eq!(
        round_trip(&sock2, public, &again, "after reconnecting").await,
        again
    );

    server.shutdown().await;
}
