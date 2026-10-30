//! The issuers of the certs of terminated hostnames, and the issuer of each
//! hostname: the one it names, else the one whose cert covers it, else the
//! default one, else a self-signed cert.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sha2::{Digest, Sha256};

// Non-poisoning locks on the handshake path, as in routes.rs
use parking_lot::{Mutex, RwLock};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::cert;
use crate::config::{AcmeSection, IssuerEntry, IssuerKind, ServerConfig, validate_issuer_list};
use crate::coverage::Coverage;
use crate::error::ServerError;
use crate::on_demand::OnDemand;
use crate::routes::host_patterns;

pub(crate) struct Issuers {
    state: RwLock<State>,
    /// For a hostname without an issuer, and for an ACME name without a cert
    fallback: OnDemand,
    cancel: CancellationToken,
}

struct State {
    issuers: HashMap<String, Arc<Issuer>>,
    default: Option<String>,
    config: ConfigIssuers,
    /// Lowercase host provisioned through the dynamic seam, to its issuer
    dynamic_hosts: HashMap<String, String>,
}

/// What the config says about the certs of its entries.
struct ConfigIssuers {
    /// Lowercase host or pattern of an entry, to its issuer
    hosts: HashMap<String, String>,
    /// Hosts and patterns of the entries with a cert file: that cert wins, so
    /// ACME orders none for them
    own_certs: HashSet<String>,
}

impl ConfigIssuers {
    fn of(config: &ServerConfig) -> Self {
        let hosts = config
            .host_issuers()
            .map(|(host, _, _, issuer)| (host.to_ascii_lowercase(), issuer.to_string()))
            .collect();
        let own_certs = config
            .host_certs()
            .filter(|(_, _, cert, _)| cert.is_some())
            .map(|(host, _, _, _)| host.to_ascii_lowercase())
            .collect();

        Self { hosts, own_certs }
    }
}

/// A loaded issuer list, ready to replace the current one.
pub(crate) struct Prepared {
    issuers: HashMap<String, Arc<Issuer>>,
    default: Option<String>,
}

struct Issuer {
    entry: IssuerEntry,
    source: Source,
    coverage: Coverage,
    /// Digest of its cert and key files, for a `local_ca` or `imported` issuer
    files: Option<[u8; 32]>,
}

/// How a hostname got its issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerChoice {
    /// Its entry names the issuer.
    Named,
    /// The cert of the issuer covers the hostname: the name constraints of a
    /// CA, or the SANs of an imported cert.
    Covered,
    /// The default issuer.
    Default,
}

/// The issuer of a hostname, and how it got it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIssuer {
    pub issuer: String,
    pub choice: IssuerChoice,
}

enum Source {
    OnDemand(OnDemand),
    Imported(Arc<CertifiedKey>),
    Acme(Acme),
}

/// One ACME state per name, so a new name never touches the certs of the others
struct Acme {
    section: AcmeSection,
    names: Mutex<HashMap<String, AcmeName>>,
}

struct AcmeName {
    resolver: Arc<dyn ResolvesServerCert>,
    cancel: CancellationToken,
}

impl Drop for Acme {
    fn drop(&mut self) {
        for name in self.names.lock().values() {
            name.cancel.cancel();
        }
    }
}

impl std::fmt::Debug for Issuers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        let mut names: Vec<&String> = state.issuers.keys().collect();
        names.sort();

        f.debug_struct("Issuers")
            .field("issuers", &names)
            .field("default", &state.default)
            .finish_non_exhaustive()
    }
}

impl Issuers {
    pub(crate) fn new(
        config: &ServerConfig,
        cancel: CancellationToken,
    ) -> Result<Self, ServerError> {
        let issuers = Self {
            state: RwLock::new(State {
                issuers: HashMap::new(),
                default: None,
                config: ConfigIssuers::of(config),
                dynamic_hosts: HashMap::new(),
            }),
            fallback: OnDemand::self_signed(),
            cancel,
        };
        issuers.set_issuers(config.effective_issuers())?;

        Ok(issuers)
    }

    /// Load `entries` without serving them. An issuer whose entry and files
    /// did not change keeps its certs and orders.
    pub(crate) fn prepare(&self, entries: Vec<IssuerEntry>) -> Result<Prepared, ServerError> {
        validate_issuer_list(&entries)?;

        let current = self.state.read().issuers.clone();
        let mut issuers = HashMap::new();

        for entry in entries {
            let issuer = match current.get(&entry.name) {
                Some(issuer)
                    if issuer.entry == entry && issuer.files == files_digest(&entry.kind) =>
                {
                    issuer.clone()
                }
                _ => Arc::new(Issuer::load(entry)?),
            };

            issuers.insert(issuer.entry.name.clone(), issuer);
        }

        let default = issuers
            .values()
            .find(|i| i.entry.default)
            .map(|i| i.entry.name.clone());

        Ok(Prepared { issuers, default })
    }

    /// Replace the issuers; a failed load changes nothing.
    pub(crate) fn set_issuers(&self, entries: Vec<IssuerEntry>) -> Result<(), ServerError> {
        let prepared = self.prepare(entries)?;
        let mut state = self.state.write();

        state.install(prepared);

        Ok(())
    }

    /// Serve the issuers of a reloaded config: `prepared`, and the issuers and
    /// cert files its entries name.
    pub(crate) fn reload(&self, config: &ServerConfig, prepared: Prepared) {
        let mut state = self.state.write();

        state.config = ConfigIssuers::of(config);
        state.install(prepared);
    }

    /// Replace the issuer names of the hostnames provisioned through the seam.
    #[cfg(feature = "dynamic")]
    pub(crate) fn set_dynamic_hosts(&self, hosts: HashMap<String, String>) {
        self.state.write().dynamic_hosts = hosts
            .into_iter()
            .map(|(host, issuer)| (host.to_ascii_lowercase(), issuer))
            .collect();
    }

    /// Order the certs of the ACME issuers for the `terminated` names, and
    /// stop the orders of the names they no longer serve.
    pub(crate) fn plan_acme(&self, terminated: &[String]) {
        let plan = self.acme_plan(terminated);
        let state = self.state.read();

        for issuer in state.issuers.values() {
            if let Source::Acme(acme) = &issuer.source {
                let names = plan.get(&issuer.entry.name).cloned().unwrap_or_default();
                acme.serve(names, &self.cancel);
            }
        }
    }

    /// The names that each ACME issuer serves among `terminated`: exact names
    /// without a cert file of their own.
    fn acme_plan(&self, terminated: &[String]) -> HashMap<String, HashSet<String>> {
        let state = self.state.read();
        let mut plan: HashMap<String, HashSet<String>> = HashMap::new();

        for host in terminated {
            let host = host.to_ascii_lowercase();
            let own_cert = host_patterns(&host)
                .iter()
                .any(|pattern| state.config.own_certs.contains(pattern));

            if host.contains('*') || own_cert {
                continue;
            }

            let Some((issuer, _)) = state.issuer_of(&host) else {
                continue;
            };

            if matches!(issuer.source, Source::Acme(_)) {
                plan.entry(issuer.entry.name.clone())
                    .or_default()
                    .insert(host);
            }
        }

        plan
    }

    /// The issuer of `host` and how it got it; `None` takes a self-signed cert.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn host_issuer(&self, host: &str) -> Option<HostIssuer> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let (issuer, choice) = self.state.read().issuer_of(&host)?;

        Some(HostIssuer {
            issuer: issuer.entry.name.clone(),
            choice,
        })
    }

    /// The names that each issuer covers, as an operator reads them.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn coverage(&self) -> HashMap<String, Vec<String>> {
        self.state
            .read()
            .issuers
            .values()
            .map(|i| (i.entry.name.clone(), i.coverage.describe()))
            .collect()
    }
}

impl State {
    fn install(&mut self, prepared: Prepared) {
        tracing::info!(
            issuers = prepared.issuers.len(),
            default = ?prepared.default,
            "cert issuers set"
        );

        self.issuers = prepared.issuers;
        self.default = prepared.default;
    }

    /// The issuer of `host`: the one of its exact entry, of its `*.domain`
    /// entry or of `*` (as the routing table picks the entry), else the one
    /// that covers it most closely, else the default.
    fn issuer_of(&self, host: &str) -> Option<(Arc<Issuer>, IssuerChoice)> {
        let named = host_patterns(host)
            .iter()
            .enumerate()
            .find_map(|(i, pattern)| {
                let config = self.config.hosts.get(pattern);

                match i {
                    0 => config.or_else(|| self.dynamic_hosts.get(pattern)),
                    _ => config,
                }
            });

        if let Some(name) = named {
            match self.issuers.get(name) {
                Some(issuer) => return Some((issuer.clone(), IssuerChoice::Named)),
                None => tracing::warn!(host = %host, issuer = %name, "unknown cert issuer"),
            }
        }

        // The name breaks a tie, so the choice does not depend on map order
        let covered = self
            .issuers
            .values()
            .filter_map(|issuer| Some((issuer.coverage.score(host)?, issuer)))
            .max_by(|(a, x), (b, y)| a.cmp(b).then_with(|| y.entry.name.cmp(&x.entry.name)));

        if let Some((_, issuer)) = covered {
            return Some((issuer.clone(), IssuerChoice::Covered));
        }

        let default = self.issuers.get(self.default.as_ref()?)?;

        Some((default.clone(), IssuerChoice::Default))
    }
}

/// Load `entries` as a start would, and drop them. Orders no cert.
pub(crate) fn check(entries: &[IssuerEntry]) -> Result<(), ServerError> {
    validate_issuer_list(entries)?;

    for entry in entries {
        Issuer::load(entry.clone())?;
    }

    Ok(())
}

/// The digest of the cert and key files of a `local_ca` or `imported` issuer,
/// so a renewed file loads again under the same entry.
fn files_digest(kind: &IssuerKind) -> Option<[u8; 32]> {
    let (IssuerKind::LocalCa {
        cert_file,
        key_file,
    }
    | IssuerKind::Imported {
        cert_file,
        key_file,
    }) = kind
    else {
        return None;
    };

    let mut hasher = Sha256::new();
    hasher.update(std::fs::read(cert_file).ok()?);
    hasher.update(std::fs::read(key_file).ok()?);

    Some(hasher.finalize().into())
}

impl Issuer {
    fn load(entry: IssuerEntry) -> Result<Self, ServerError> {
        let files = files_digest(&entry.kind);
        let (source, coverage) = match &entry.kind {
            IssuerKind::LocalCa {
                cert_file,
                key_file,
            } => {
                let local_ca = OnDemand::local_ca(cert_file, key_file)?;
                let coverage = local_ca.coverage();
                (Source::OnDemand(local_ca), coverage)
            }
            IssuerKind::SelfSigned => (
                Source::OnDemand(OnDemand::self_signed()),
                Coverage::default(),
            ),
            IssuerKind::Imported {
                cert_file,
                key_file,
            } => {
                let (chain, key) = cert::load_chain(cert_file, key_file)?;
                let coverage = Coverage::from_sans(&chain[0]);
                let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
                let certified = Arc::new(CertifiedKey::new(chain, signing_key));
                (Source::Imported(certified), coverage)
            }
            IssuerKind::Acme(section) => {
                let acme = Acme {
                    section: section.clone(),
                    names: Mutex::new(HashMap::new()),
                };
                (Source::Acme(acme), Coverage::default())
            }
        };

        tracing::info!(
            issuer = %entry.name,
            kind = ?entry.kind,
            covers = ?coverage.describe(),
            "cert issuer loaded"
        );

        Ok(Self {
            entry,
            source,
            coverage,
            files,
        })
    }
}

impl Acme {
    fn serve(&self, wanted: HashSet<String>, cancel: &CancellationToken) {
        let mut names = self.names.lock();

        names.retain(|name, state| {
            let keep = wanted.contains(name);

            if !keep {
                state.cancel.cancel();
                tracing::info!(name = %name, "acme: stopped");
            }

            keep
        });

        for name in wanted {
            if names.contains_key(&name) {
                continue;
            }

            let cancel = cancel.child_token();
            let resolver = start_acme(&self.section, &name, cancel.clone());
            tracing::info!(name = %name, "acme: ordering a cert");
            names.insert(name, AcmeName { resolver, cancel });
        }
    }
}

/// One ACME state that orders and renews the cert of `name`, tied to `cancel`.
fn start_acme(
    section: &AcmeSection,
    name: &str,
    cancel: CancellationToken,
) -> Arc<dyn ResolvesServerCert> {
    use futures_util::StreamExt;
    use rustls_acme::{AcmeConfig, caches::DirCache};

    let mut state = AcmeConfig::new([name])
        .contact_push(&section.contact)
        .cache(DirCache::new(section.cache_dir.clone()))
        .directory_lets_encrypt(section.production)
        .state();
    let resolver = state.resolver();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                event = state.next() => match event {
                    Some(Ok(ok)) => tracing::info!("acme: {:?}", ok),
                    Some(Err(err)) => tracing::warn!(error = ?err, "acme error"),
                    None => break,
                }
            }
        }
    });

    resolver
}

impl ResolvesServerCert for Issuers {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = ch.server_name()?.trim_end_matches('.').to_ascii_lowercase();
        let issuer = self.state.read().issuer_of(&host);

        let Some((issuer, _)) = issuer else {
            return self.fallback.cert_for(&host);
        };

        match &issuer.source {
            Source::OnDemand(on_demand) => on_demand.cert_for(&host),
            Source::Imported(certified) => Some(certified.clone()),
            Source::Acme(acme) => {
                let resolver = acme.names.lock().get(&host).map(|n| n.resolver.clone());

                // Until its order completes, a name gets the self-signed cert
                resolver
                    .and_then(|r| r.resolve(ch))
                    .or_else(|| self.fallback.cert_for(&host))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuers(toml: &str) -> Issuers {
        let config = ServerConfig::from_toml_str(toml).unwrap();
        config.validate().unwrap();

        Issuers::new(&config, CancellationToken::new()).unwrap()
    }

    const CONFIG: &str = r#"
        listen_addr = "127.0.0.1:0"

        [[issuers]]
        name = "le"
        kind = "acme"
        contact = "mailto:ops@example.com"
        cache_dir = "/tmp/tuyau-acme-test"

        [[issuers]]
        name = "dev"
        kind = "self_signed"
        default = true

        [[upstreams]]
        host = "public.example.com"
        local_addr = "127.0.0.1:1"
        issuer = "le"

        [[upstreams]]
        host = "*.lan.example.com"
        local_addr = "127.0.0.1:1"

        [[upstreams]]
        host = "own.example.com"
        local_addr = "127.0.0.1:1"
        tls_cert_file = "own.pem"
        tls_key_file = "own.key"
    "#;

    fn issuer_name(issuers: &Issuers, host: &str) -> Option<String> {
        issuers.host_issuer(host).map(|h| h.issuer)
    }

    #[test]
    fn a_host_takes_its_named_issuer_else_the_default() {
        let issuers = issuers(CONFIG);

        assert_eq!(
            issuer_name(&issuers, "public.example.com").as_deref(),
            Some("le")
        );
        assert_eq!(
            issuer_name(&issuers, "a.lan.example.com").as_deref(),
            Some("dev")
        );
    }

    #[cfg(feature = "dynamic")]
    #[test]
    fn a_provisioned_host_names_its_issuer_and_a_config_entry_wins() {
        let issuers = issuers(CONFIG);

        issuers.set_dynamic_hosts(HashMap::from([
            ("App.example.com".to_string(), "le".to_string()),
            ("public.example.com".to_string(), "dev".to_string()),
        ]));

        assert_eq!(
            issuer_name(&issuers, "app.example.com").as_deref(),
            Some("le")
        );
        assert_eq!(
            issuer_name(&issuers, "public.example.com").as_deref(),
            Some("le")
        );
    }

    /// The plan only: starting an order would reach Let's Encrypt.
    #[test]
    fn acme_orders_exact_names_of_its_own_without_a_cert_file() {
        let issuers = issuers(CONFIG);

        let plan = issuers.acme_plan(&[
            "public.example.com".into(),
            "own.example.com".into(),
            "*.lan.example.com".into(),
            "x.lan.example.com".into(),
        ]);

        assert_eq!(
            plan.get("le"),
            Some(&HashSet::from(["public.example.com".to_string()]))
        );
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn an_unchanged_issuer_keeps_its_state_and_a_new_default_applies() {
        let issuers = issuers(CONFIG);
        let before = issuers.state.read().issuers["dev"].clone();

        let mut entries = issuers
            .state
            .read()
            .issuers
            .values()
            .map(|i| i.entry.clone())
            .collect::<Vec<_>>();
        for entry in &mut entries {
            entry.default = entry.name == "le";
        }
        let dev = entries.iter().position(|e| e.name == "dev").unwrap();
        entries[dev].default = false;

        issuers.set_issuers(entries).unwrap();

        assert_eq!(
            issuer_name(&issuers, "a.lan.example.com").as_deref(),
            Some("le")
        );
        assert!(!Arc::ptr_eq(&before, &issuers.state.read().issuers["dev"]));

        let same = issuers.state.read().issuers["le"].clone();
        let entries = issuers
            .state
            .read()
            .issuers
            .values()
            .map(|i| i.entry.clone())
            .collect();
        issuers.set_issuers(entries).unwrap();

        assert!(Arc::ptr_eq(&same, &issuers.state.read().issuers["le"]));
    }

    #[test]
    fn a_bad_issuer_list_changes_nothing() {
        let issuers = issuers(CONFIG);
        let missing = IssuerEntry {
            name: "home".into(),
            default: true,
            kind: IssuerKind::LocalCa {
                cert_file: "/nonexistent/ca.pem".into(),
                key_file: "/nonexistent/ca.key".into(),
            },
        };

        assert!(issuers.set_issuers(vec![missing]).is_err());
        assert_eq!(issuers.state.read().issuers.len(), 2);
        assert_eq!(issuers.state.read().default.as_deref(), Some("dev"));
    }

    /// Writes a CA limited to `permitted` names into `dir`; gives its config
    /// lines as a `local_ca` issuer named `name`.
    fn ca_issuer(dir: &std::path::Path, name: &str, permitted: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.name_constraints = Some(rcgen::NameConstraints {
            permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName(permitted.into())],
            excluded_subtrees: vec![],
        });
        let ca = params.self_signed(&key).unwrap();

        let cert_file = dir.join(format!("{name}.pem"));
        let key_file = dir.join(format!("{name}.key"));
        std::fs::write(&cert_file, ca.pem()).unwrap();
        std::fs::write(&key_file, key.serialize_pem()).unwrap();

        format!(
            "[[issuers]]\nname = \"{name}\"\nkind = \"local_ca\"\n\
             cert_file = \"{}\"\nkey_file = \"{}\"\n",
            cert_file.display(),
            key_file.display()
        )
    }

    fn covered_config(dir: &std::path::Path) -> Issuers {
        issuers(&format!(
            r#"
            listen_addr = "127.0.0.1:0"
            {home}
            {wide}
            [[issuers]]
            name = "le"
            kind = "acme"
            contact = "mailto:ops@example.com"
            cache_dir = "/tmp/tuyau-acme-test"
            default = true

            [[issuers]]
            name = "dev"
            kind = "self_signed"

            [[upstreams]]
            host = "*.lan.example.com"
            local_addr = "127.0.0.1:1"

            [[upstreams]]
            host = "named.lan.example.com"
            local_addr = "127.0.0.1:1"
            issuer = "dev"
            "#,
            home = ca_issuer(dir, "home", "lan.example.com"),
            wide = ca_issuer(dir, "wide", "example.net"),
        ))
    }

    #[test]
    fn a_host_takes_the_issuer_that_covers_it_unless_its_entry_names_one() {
        let dir = tempfile::TempDir::new().unwrap();
        let issuers = covered_config(dir.path());
        let issuer = |host: &str| issuers.host_issuer(host).unwrap();

        assert_eq!(
            issuer("nas.lan.example.com"),
            HostIssuer {
                issuer: "home".into(),
                choice: IssuerChoice::Covered
            }
        );
        assert_eq!(issuer("named.lan.example.com").choice, IssuerChoice::Named);
        assert_eq!(
            issuer("public.example.com"),
            HostIssuer {
                issuer: "le".into(),
                choice: IssuerChoice::Default
            }
        );
        assert_eq!(issuers.coverage()["home"], ["lan.example.com"]);
        assert!(issuers.coverage()["le"].is_empty());
    }

    #[test]
    fn the_issuer_with_the_narrower_cover_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let issuers = issuers(&format!(
            "listen_addr = \"127.0.0.1:0\"\n{}\n{}\n\
             [[upstreams]]\nhost = \"a.example.com\"\nlocal_addr = \"127.0.0.1:1\"\n",
            ca_issuer(dir.path(), "wide", "example.com"),
            ca_issuer(dir.path(), "narrow", "lan.example.com"),
        ));

        assert_eq!(
            issuer_name(&issuers, "nas.lan.example.com").as_deref(),
            Some("narrow")
        );
        assert_eq!(
            issuer_name(&issuers, "www.example.com").as_deref(),
            Some("wide")
        );
    }

    #[test]
    fn acme_orders_no_cert_for_a_name_that_a_ca_covers() {
        let dir = tempfile::TempDir::new().unwrap();
        let issuers = covered_config(dir.path());

        let plan = issuers.acme_plan(&["public.example.com".into(), "nas.lan.example.com".into()]);

        assert_eq!(
            plan.get("le"),
            Some(&HashSet::from(["public.example.com".to_string()]))
        );
    }
}
