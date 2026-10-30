use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    #[error("cert: {0}")]
    Cert(#[from] CertError),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("client_ca_file: {0}")]
    ClientCa(String),

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

    #[error("'{0}' must set both tls_cert_file and tls_key_file, or neither")]
    HostCertPair(String),

    #[error("'{0}' sets a cert in passthrough mode, where the server holds no cert")]
    HostCertPassthrough(String),

    #[error("host '{0}' is not a name, and an upstream host is not a name, '*.name' or '*'")]
    HostPattern(String),

    #[error("issuers cannot be set with acme or tls_cert_file, their short form")]
    IssuersWithLegacy,

    #[error("duplicate issuer name: {0}")]
    DuplicateIssuer(String),

    #[error("more than one issuer sets default = true")]
    DefaultIssuers,

    #[error("hostname '{host}' references unknown issuer '{issuer}'")]
    UnknownIssuer { host: String, issuer: String },

    #[error("'{0}' names an issuer in passthrough mode, where the server holds no cert")]
    IssuerPassthrough(String),

    #[error("'{0}' sets both a cert file and an issuer")]
    IssuerWithCert(String),

    #[error("'{0}' is a pattern, and ACME issues certs for names only")]
    AcmePattern(String),
}

#[derive(Debug, Error)]
pub enum CertError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("pem: no certificate found in {0}")]
    PemNoCert(String),

    #[error("ca: {0} is not a CA cert: {1}")]
    BadCa(String, String),

    #[error("pem: no private key found in {0}")]
    PemNoKey(String),

    #[error("issuer key {0}: {1}")]
    IssuerKey(String, String),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
}
