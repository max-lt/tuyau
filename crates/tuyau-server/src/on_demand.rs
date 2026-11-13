//! Certs issued at the first handshake of each hostname: signed by a local CA
//! (its key on this machine, the clients trust it), or self-signed.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;

use crate::cert;
use crate::coverage::Coverage;
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

pub(crate) struct OnDemand {
    /// `None` signs each cert with its own key.
    ca: Option<Box<Ca>>,
    issued: Mutex<HashMap<String, Issued>>,
}

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// The CA itself and whatever signed it, sent after each issued cert. An
    /// intermediate CA is unusable without it: the client trusts the root and
    /// has no way to fetch what sits in between.
    chain: Vec<CertificateDer<'static>>,
}

struct Issued {
    certified: Arc<CertifiedKey>,
    renew_at: OffsetDateTime,
}

impl std::fmt::Debug for OnDemand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemand")
            .field("local_ca", &self.ca.is_some())
            .field("issued", &self.issued.lock().len())
            .finish_non_exhaustive()
    }
}

impl OnDemand {
    pub(crate) fn self_signed() -> Self {
        Self {
            ca: None,
            issued: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn local_ca(cert_file: &Path, key_file: &Path) -> Result<Self, CertError> {
        let (chain, key_der) = cert::load_chain(cert_file, key_file)?;
        let key_error =
            |reason: String| CertError::IssuerKey(key_file.display().to_string(), reason);

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
        let cert = CertificateParams::from_ca_cert_der(&chain[0])?.self_signed(&key)?;

        Ok(Self {
            ca: Some(Box::new(Ca { cert, key, chain })),
            issued: Mutex::new(HashMap::new()),
        })
    }

    /// The names that the CA may sign; none for a self-signed issuer.
    pub(crate) fn coverage(&self) -> Coverage {
        let constraints = self
            .ca
            .as_ref()
            .and_then(|ca| ca.cert.params().name_constraints.as_ref());

        Coverage::from_constraints(constraints)
    }

    /// The cert of `host`, issued now if it has none or if it nears its end.
    pub(crate) fn cert_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
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
                tracing::error!(host = %host, error = %e, "cannot issue a cert");
                return None;
            }
        };

        tracing::info!(host = %host, local_ca = self.ca.is_some(), "issued a cert");

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
        params.not_before = now - BACKDATE;
        params.not_after = now + VALIDITY;

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let chain = match &self.ca {
            Some(ca) => {
                params.use_authority_key_identifier_extension = true;
                let cert = params.signed_by(&key, &ca.cert, &ca.key)?;
                let mut chain = vec![cert.der().clone()];
                chain.extend(ca.chain.iter().cloned());
                chain
            }
            None => vec![params.self_signed(&key)?.der().clone()],
        };

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;

        Ok(Issued {
            certified: Arc::new(CertifiedKey::new(chain, signing_key)),
            renew_at: now + VALIDITY - RENEW_BEFORE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    /// Writes a CA cert and its key into `dir`; gives the cert file, the key
    /// file and the CA cert.
    fn write_ca(dir: &Path) -> (PathBuf, PathBuf, CertificateDer<'static>) {
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

        let cert_file = dir.join("ca.pem");
        let key_file = dir.join("ca.key");
        std::fs::write(&cert_file, ca.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();

        (cert_file, key_file, ca.der().clone())
    }

    fn verify(root: &CertificateDer<'static>, cert: &CertifiedKey, host: &str) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();

        verifier
            .verify_server_cert(
                &cert.cert[0],
                &cert.cert[1..],
                &ServerName::try_from(host.to_string()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .unwrap();
    }

    fn local_ca(dir: &Path) -> (OnDemand, CertificateDer<'static>) {
        let (cert_file, key_file, ca_der) = write_ca(dir);
        (OnDemand::local_ca(&cert_file, &key_file).unwrap(), ca_der)
    }

    #[test]
    fn each_host_gets_a_cert_that_the_ca_verifies_and_keeps_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let (ca, ca_der) = local_ca(dir.path());

        let a = ca.cert_for("A.Example.com.").unwrap();
        let b = ca.cert_for("b.example.com").unwrap();

        verify(&ca_der, &a, "a.example.com");
        verify(&ca_der, &b, "b.example.com");
        assert!(Arc::ptr_eq(&a, &ca.cert_for("a.example.com").unwrap()));
        assert_ne!(a.cert[0], b.cert[0]);
    }

    #[test]
    fn a_self_signed_cert_names_the_host_and_has_no_issuer_above_it() {
        let own = OnDemand::self_signed().cert_for("a.example.com").unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&own.cert[0]).unwrap();

        assert_eq!(parsed.subject(), parsed.issuer());
        assert_eq!(
            parsed
                .subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "a.example.com"
        );
    }

    #[test]
    fn a_cert_near_its_end_is_issued_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let (ca, _) = local_ca(dir.path());

        let first = ca.cert_for("a.example.com").unwrap();
        ca.issued.lock().get_mut("a.example.com").unwrap().renew_at = OffsetDateTime::now_utc();

        assert!(!Arc::ptr_eq(&first, &ca.cert_for("a.example.com").unwrap()));
    }

    #[test]
    fn the_cache_stays_under_its_bound() {
        let dir = tempfile::TempDir::new().unwrap();
        let (ca, _) = local_ca(dir.path());

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
        let (cert_file, _, _) = write_ca(dir.path());
        let other = dir.path().join("other.key");
        std::fs::write(&other, KeyPair::generate().unwrap().serialize_pem()).unwrap();

        assert!(matches!(
            OnDemand::local_ca(&cert_file, &other),
            Err(CertError::IssuerKey(..))
        ));
    }
    /// Writes a root, and under it an intermediate CA whose cert file holds
    /// both; gives the intermediate's cert file, its key file and the root.
    fn write_intermediate(dir: &Path) -> (PathBuf, PathBuf, CertificateDer<'static>) {
        let root_key = KeyPair::generate().unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(1));
        root.distinguished_name
            .push(DnType::CommonName, "test root");
        root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = root.self_signed(&root_key).unwrap();

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "test authority");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(".example.com".to_string())],
            excluded_subtrees: vec![],
        });
        let intermediate = params.signed_by(&key, &root, &root_key).unwrap();

        let cert_file = dir.join("intermediate.pem");
        let key_file = dir.join("intermediate.key");
        std::fs::write(&cert_file, intermediate.pem() + &root.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();

        (cert_file, key_file, root.der().clone())
    }

    #[test]
    fn an_intermediate_sends_its_own_cert_so_the_root_alone_verifies_the_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let (cert_file, key_file, root) = write_intermediate(dir.path());
        let ca = OnDemand::local_ca(&cert_file, &key_file).unwrap();

        let cert = ca.cert_for("a.example.com").unwrap();

        assert_eq!(cert.cert.len(), 3);
        verify(&root, &cert, "a.example.com");
    }
}
