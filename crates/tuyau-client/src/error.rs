use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    #[error("invalid server_addr (expected 'host:port'): {0}")]
    InvalidServerAddr(String),

    #[error("dns: no addresses resolved for '{0}'")]
    DnsEmpty(String),

    #[error("dns: {0}")]
    Dns(std::io::Error),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("quic: invalid crypto config: {0}")]
    QuicCrypto(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("quic: connect: {0}")]
    QuicConnect(#[from] quinn::ConnectError),

    #[error("quic: connection: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol: {0}")]
    Protocol(#[from] tuyau_protocol::ProtocolError),

    #[error("server rejected: {0}")]
    Rejected(String),

    #[error("server did not respond to hello within timeout")]
    ResponseTimeout,

    #[error("connect timed out (server unreachable?)")]
    ConnectTimeout,

    #[error("server closed stream before sending response")]
    StreamClosedBeforeResponse,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("ingress[{index}]: {reason}")]
    InvalidIngress { index: usize, reason: String },
}
