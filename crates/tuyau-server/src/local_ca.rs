//! Certs that a local CA issues at the first handshake of each terminated
//! hostname without a cert of its own. The CA key is on this machine and the
//! clients trust the CA, so no ACME challenge is needed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;

use crate::cert;
use crate::config::LocalCaSection;
use crate::error::CertError;

/// Validity of an issued cert. macOS refuses a server cert valid for more than
/// 825 days, also from a CA that the user added.
const VALIDITY: Duration = Duration::from_secs(30 * 24 * 3600);
/// The server issues a cert again when it has this much validity left.
const RENEW_BEFORE: Duration = Duration::from_secs(10 * 24 * 3600);
/// A cert starts this much before its issue, for a client clock that is late.
const BACKDATE: Duration = Duration::from_secs(3600);
/// Bound on the issued certs in memory. Under a `*` or `*.name` route the
/// client picks the SNI, so it must not grow the cache without end.
const MAX_ISSUED: usize = 1024;

pub(crate) struct LocalCa {
    ca: rcgen::Certificate,
    key: KeyPair,
    issued: Mutex<HashMap<String, Issued>>,
}

struct Issued {
    certified: Arc<CertifiedKey>,
    renew_at: OffsetDateTime,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("issued", &self.issued.lock().len())
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    pub(crate) fn load(section: &LocalCaSection) -> Result<Self, CertError> {
        let (chain, key_der) = cert::load_chain(&section.cert_file, &section.key_file)?;
        let key_error =
            |reason: String| CertError::LocalCaKey(section.key_file.display().to_string(), reason);

        // rcgen on ring reads PKCS#8 keys only
        if !matches!(key_der, PrivateKeyDer::Pkcs8(_)) {
            return Err(key_error(
                "not PKCS#8, convert it with `openssl pkcs8 -topk8 -nocrypt`".to_string(),
            ));
        }

        // With the key of another cert, every issued cert would fail the check
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
        CertifiedKey::new(vec![chain[0].clone()], signing_key)
            .keys_match()
            .map_err(|e| key_error(e.to_string()))?;

        let key = KeyPair::try_from(&key_der)?;
        // rcgen signs with a Certificate: this copy keeps the subject and the
        // key identifier of the CA, which the issued certs name as issuer
        let ca = CertificateParams::from_ca_cert_der(&chain[0])?.self_signed(&key)?;

        Ok(Self {
            ca,
            key,
            issued: Mutex::new(HashMap::new()),
        })
    }

    /// The cert of `host`, issued now if it has none or if it nears its end.
    fn cert_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let now = OffsetDateTime::now_utc();
        let mut issued = self.issued.lock();

        if let Some(cert) = issued.get(&host)
            && now < cert.renew_at
        {
            return Some(cert.certified.clone());
        }

        let cert = match self.issue(&host, now) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(host = %host, error = %e, "local_ca: cannot issue a cert");
                return None;
            }
        };

        tracing::info!(host = %host, "local_ca: issued a cert");

        if issued.len() >= MAX_ISSUED && !issued.contains_key(&host) {
            issued.clear();
        }

        let certified = cert.certified.clone();
        issued.insert(host, cert);

        Some(certified)
    }

    fn issue(&self, host: &str, now: OffsetDateTime) -> Result<Issued, CertError> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - BACKDATE;
        params.not_after = now + VALIDITY;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.signed_by(&key, &self.ca, &self.key)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;

        Ok(Issued {
            certified: Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing_key)),
            renew_at: now + VALIDITY - RENEW_BEFORE,
        })
    }
}

impl ResolvesServerCert for LocalCa {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.cert_for(ch.server_name()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// Writes a CA cert and its key into `dir`; gives the section and the CA
    /// cert.
    fn write_ca(dir: &Path) -> (LocalCaSection, CertificateDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "test authority");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![
                rcgen::GeneralSubtree::DnsName(".example.com".to_string()),
                rcgen::GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4([127, 0, 0, 1], [255; 4])),
            ],
            excluded_subtrees: vec![],
        });
        let ca = params.self_signed(&key).unwrap();

        let section = LocalCaSection {
            cert_file: dir.join("ca.pem"),
            key_file: dir.join("ca.key"),
        };
        std::fs::write(&section.cert_file, ca.pem()).unwrap();
        std::fs::write(&section.key_file, key.serialize_pem()).unwrap();

        (section, ca.der().clone())
    }

    fn verify(ca: &CertificateDer<'static>, cert: &CertifiedKey, host: &str) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();

        verifier
            .verify_server_cert(
                &cert.cert[0],
                &[],
                &ServerName::try_from(host.to_string()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
    }

    #[test]
    fn each_host_gets_a_cert_that_the_ca_verifies_and_keeps_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let (section, ca_der) = write_ca(dir.path());
        let ca = LocalCa::load(&section).unwrap();

        let a = ca.cert_for("A.Example.com.").unwrap();
        let b = ca.cert_for("b.example.com").unwrap();

        verify(&ca_der, &a, "a.example.com");
        verify(&ca_der, &b, "b.example.com");
        assert!(Arc::ptr_eq(&a, &ca.cert_for("a.example.com").unwrap()));
        assert_ne!(a.cert[0], b.cert[0]);
    }

    #[test]
    fn a_cert_near_its_end_is_issued_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let (section, _) = write_ca(dir.path());
        let ca = LocalCa::load(&section).unwrap();

        let first = ca.cert_for("a.example.com").unwrap();
        ca.issued.lock().get_mut("a.example.com").unwrap().renew_at = OffsetDateTime::now_utc();

        assert!(!Arc::ptr_eq(&first, &ca.cert_for("a.example.com").unwrap()));
    }

    #[test]
    fn the_cache_stays_under_its_bound() {
        let dir = tempfile::TempDir::new().unwrap();
        let (section, _) = write_ca(dir.path());
        let ca = LocalCa::load(&section).unwrap();

        let certified = ca.cert_for("a.example.com").unwrap();
        let renew_at = OffsetDateTime::now_utc() + VALIDITY;

        {
            let mut issued = ca.issued.lock();

            for i in 0..MAX_ISSUED {
                let certified = certified.clone();
                issued.insert(
                    format!("{i}.example.com"),
                    Issued {
                        certified,
                        renew_at,
                    },
                );
            }
        }

        ca.cert_for("new.example.com").unwrap();

        assert_eq!(ca.issued.lock().len(), 1);
    }

    #[test]
    fn the_key_of_another_cert_fails_the_load() {
        let dir = tempfile::TempDir::new().unwrap();
        let (section, _) = write_ca(dir.path());
        let other = dir.path().join("other.key");
        std::fs::write(&other, KeyPair::generate().unwrap().serialize_pem()).unwrap();

        let section = LocalCaSection {
            key_file: other,
            ..section
        };

        assert!(matches!(
            LocalCa::load(&section),
            Err(CertError::LocalCaKey(..))
        ));
    }
}
