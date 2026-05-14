use std::fs;
use std::io::BufReader;
use std::path::Path;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

use crate::error::CertError;

const CERT_FILE: &str = "tunnel-cert.pem";
const KEY_FILE: &str = "tunnel-key.pem";

const PUBLIC_CERT_FILE: &str = "public-cert.pem";
const PUBLIC_KEY_FILE: &str = "public-key.pem";

pub struct CertMaterial {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub fingerprint: [u8; 32],
}

pub fn load_or_generate(dir: &Path) -> Result<CertMaterial, CertError> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        load(&cert_path, &key_path)
    } else {
        generate(dir, &cert_path, &key_path)
    }
}

fn load(cert_path: &Path, key_path: &Path) -> Result<CertMaterial, CertError> {
    let cert_der = read_first_cert(cert_path)?;
    let key_der = read_first_pkcs8_key(key_path)?;
    let fingerprint = sha256(&cert_der);

    Ok(CertMaterial {
        cert_der,
        key_der,
        fingerprint,
    })
}

fn read_first_cert(path: &Path) -> Result<CertificateDer<'static>, CertError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| CertError::PemNoCert(path.display().to_string()))??;

    Ok(cert)
}

fn read_first_pkcs8_key(path: &Path) -> Result<PrivateKeyDer<'static>, CertError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .ok_or_else(|| CertError::PemNoKey(path.display().to_string()))??;

    Ok(PrivateKeyDer::Pkcs8(key))
}

fn generate(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<CertMaterial, CertError> {
    fs::create_dir_all(dir)?;

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec!["tuyau-tunnel".to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "tuyau-tunnel");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, cert_pem.as_bytes())?;
    write_key_secure(key_path, key_pem.as_bytes())?;

    let cert_der = cert.der().clone();
    let key_der_bytes = key_pair.serialize_der();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));
    let fingerprint = sha256(&cert_der);

    Ok(CertMaterial {
        cert_der,
        key_der,
        fingerprint,
    })
}

/// Generate a self-signed certificate covering all `hostnames` as SANs, for
/// the public TLS listener. Regenerated on every server boot — this cert is
/// not pinned by anyone, so churn is fine. ACME (M5e) will eventually replace
/// this code path with real, browser-trusted certs.
pub fn generate_public_cert(hostnames: &[String], dir: &Path) -> Result<CertMaterial, CertError> {
    fs::create_dir_all(dir)?;

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let san_list = if hostnames.is_empty() {
        // Should not happen in practice (caller filters terminated hostnames
        // before invoking), but rcgen rejects empty SAN lists, so guard.
        vec!["tuyau-public".to_string()]
    } else {
        hostnames.to_vec()
    };
    let mut params = CertificateParams::new(san_list)?;
    let mut dn = DistinguishedName::new();
    let cn = hostnames
        .first()
        .map(String::as_str)
        .unwrap_or("tuyau-public");
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair)?;

    let cert_path = dir.join(PUBLIC_CERT_FILE);
    let key_path = dir.join(PUBLIC_KEY_FILE);
    fs::write(&cert_path, cert.pem().as_bytes())?;
    write_key_secure(&key_path, key_pair.serialize_pem().as_bytes())?;

    let cert_der = cert.der().clone();
    let key_der_bytes = key_pair.serialize_der();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));
    let fingerprint = sha256(&cert_der);

    Ok(CertMaterial {
        cert_der,
        key_der,
        fingerprint,
    })
}

#[cfg(unix)]
fn write_key_secure(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents)
}

#[cfg(not(unix))]
fn write_key_secure(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    fs::write(path, contents)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
