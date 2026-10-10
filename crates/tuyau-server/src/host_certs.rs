//! The certs that hostname and upstream entries set for themselves, chosen by
//! SNI before the server-wide resolver (ACME, `tls_cert_file` or self-signed).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::cert;
use crate::config::ServerConfig;
use crate::error::ServerError;

#[derive(Debug, Default)]
pub(crate) struct HostCerts(HashMap<String, Arc<CertifiedKey>>);

impl HostCerts {
    /// Loads each cert file once, also when several entries share it.
    pub(crate) fn load(config: &ServerConfig) -> Result<Self, ServerError> {
        let mut loaded: HashMap<(&PathBuf, &PathBuf), Arc<CertifiedKey>> = HashMap::new();
        let mut certs = HashMap::new();

        for (host, _, cert_file, key_file) in config.host_certs() {
            let (Some(cert_file), Some(key_file)) = (cert_file, key_file) else {
                continue;
            };

            let certified = match loaded.get(&(cert_file, key_file)) {
                Some(certified) => certified.clone(),
                None => {
                    let (chain, key) = cert::load_chain(cert_file, key_file)?;
                    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
                        .map_err(ServerError::Tls)?;
                    let certified = Arc::new(CertifiedKey::new(chain, signing_key));

                    tracing::info!(cert = %cert_file.display(), "serving static TLS cert for hostnames");
                    loaded.insert((cert_file, key_file), certified.clone());
                    certified
                }
            };

            certs.insert(host.to_ascii_lowercase(), certified);
        }

        Ok(Self(certs))
    }

    fn select(&self, host: &str) -> Option<&Arc<CertifiedKey>> {
        self.0.get(&host.trim_end_matches('.').to_ascii_lowercase())
    }

    /// Whether `host` has its own cert, so ACME and the self-signed cert can
    /// leave it out.
    pub(crate) fn covers(&self, host: &str) -> bool {
        self.select(host).is_some()
    }

    /// A resolver that serves these certs and asks `default` for the other
    /// hostnames.
    pub(crate) fn resolver(
        self,
        default: Arc<dyn ResolvesServerCert>,
    ) -> Arc<dyn ResolvesServerCert> {
        if self.0.is_empty() {
            return default;
        }

        Arc::new(HostCertResolver {
            certs: self,
            default,
        })
    }
}

#[derive(Debug)]
struct HostCertResolver {
    certs: HostCerts,
    default: Arc<dyn ResolvesServerCert>,
}

impl ResolvesServerCert for HostCertResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let own = ch.server_name().and_then(|sni| self.certs.select(sni));

        match own {
            Some(certified) => Some(certified.clone()),
            None => self.default.resolve(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Writes a self-signed cert for `host` and its key into `dir`.
    fn write_cert(dir: &Path, host: &str) -> (PathBuf, PathBuf) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![host.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();

        let cert_file = dir.join(format!("{host}.crt"));
        let key_file = dir.join(format!("{host}.key"));
        std::fs::write(&cert_file, cert.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();

        (cert_file, key_file)
    }

    fn config(toml: &str) -> ServerConfig {
        let config = ServerConfig::from_toml_str(toml).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn each_host_gets_the_cert_of_its_entry_and_a_shared_file_loads_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let (a_cert, a_key) = write_cert(dir.path(), "a.example.com");
        let (b_cert, b_key) = write_cert(dir.path(), "b.example.org");

        let certs = HostCerts::load(&config(&format!(
            r#"
            listen_addr = "127.0.0.1:0"
            clients = []

            [[upstreams]]
            host = "a.example.com"
            local_addr = "127.0.0.1:1"
            tls_cert_file = "{a_cert}"
            tls_key_file = "{a_key}"

            [[upstreams]]
            host = "www.a.example.com"
            local_addr = "127.0.0.1:1"
            tls_cert_file = "{a_cert}"
            tls_key_file = "{a_key}"

            [[upstreams]]
            host = "b.example.org"
            local_addr = "127.0.0.1:1"
            tls_mode = "tls_offload"
            tls_cert_file = "{b_cert}"
            tls_key_file = "{b_key}"

            [[upstreams]]
            host = "default.example.net"
            local_addr = "127.0.0.1:1"
            "#,
            a_cert = a_cert.display(),
            a_key = a_key.display(),
            b_cert = b_cert.display(),
            b_key = b_key.display(),
        )))
        .unwrap();

        let a = certs.select("a.example.com").unwrap();
        let b = certs.select("B.Example.ORG.").unwrap();

        assert!(Arc::ptr_eq(a, certs.select("www.a.example.com").unwrap()));
        assert_ne!(a.cert[0], b.cert[0]);
        assert!(!certs.covers("default.example.net"));
        assert!(!certs.covers("c.example.com"));
    }

    #[test]
    fn a_cert_file_that_does_not_exist_fails_the_load() {
        let certs = HostCerts::load(&config(
            r#"
            listen_addr = "127.0.0.1:0"
            clients = []

            [[upstreams]]
            host = "a.example.com"
            local_addr = "127.0.0.1:1"
            tls_cert_file = "/nonexistent/a.crt"
            tls_key_file = "/nonexistent/a.key"
            "#,
        ));

        assert!(certs.is_err());
    }
}
