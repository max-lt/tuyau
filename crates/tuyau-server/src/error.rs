use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    #[error("cert: {0}")]
    Cert(#[from] CertError),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("quic: invalid crypto config: {0}")]
    QuicCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("quic: connection: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol: {0}")]
    Protocol(#[from] tuyau_protocol::ProtocolError),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("no clients configured")]
    NoClients,

    #[error("parse error: {0}")]
    Parse(String),

    #[error("duplicate client name: {0}")]
    DuplicateClient(String),

    #[error("duplicate hostname: {0}")]
    DuplicateHost(String),

    #[error("hostname '{host}' references unknown client '{client}'")]
    UnknownClient { host: String, client: String },

    #[error("acme.contact must be a mailto: URL, got '{0}'")]
    AcmeContact(String),

    #[error("upstream '{0}' must set exactly one of local_addr / local_socket")]
    UpstreamTarget(String),

    #[error("duplicate udp route name: {0}")]
    DuplicateUdpRoute(String),

    #[error("udp route name '{0}' must be 1-64 chars of [A-Za-z0-9._-] (it rides every datagram)")]
    UdpRouteName(String),

    #[error("udp route '{0}' must set exactly one of client / local_addr")]
    UdpTarget(String),

    #[error("udp route '{0}' listens on listen_addr, which the QUIC tunnel already holds")]
    UdpPortConflictsWithTunnel(String),

    #[error("duplicate udp listen_addr: {0}")]
    DuplicateUdpListenAddr(std::net::SocketAddr),
}

#[derive(Debug, Error)]
pub enum CertError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("pem: no certificate found in {0}")]
    PemNoCert(String),

    #[error("pem: no private key found in {0}")]
    PemNoKey(String),
}
