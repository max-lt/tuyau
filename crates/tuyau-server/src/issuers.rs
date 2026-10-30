//! The issuers of the certs of terminated hostnames, and the issuer of each
//! hostname: the one it names, else the default one, else a self-signed cert.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// Non-poisoning locks on the handshake path, as in routes.rs
use parking_lot::{Mutex, RwLock};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;

use crate::cert;
use crate::config::{AcmeSection, IssuerEntry, IssuerKind, ServerConfig, validate_issuer_list};
use crate::error::ServerError;
use crate::on_demand::OnDemand;
use crate::routes::host_patterns;

pub(crate) struct Issuers {
    state: RwLock<State>,
    /// For a hostname without an issuer, and for an ACME name without a cert
    fallback: OnDemand,
    /// Hosts and patterns of the entries with a cert file: that cert wins, so
    /// ACME orders none for them
    own_certs: HashSet<String>,
    cancel: CancellationToken,
}

struct State {
    issuers: HashMap<String, Arc<Issuer>>,
    default: Option<String>,
    /// Lowercase host or pattern of a config entry, to its issuer
    config_hosts: HashMap<String, String>,
    /// Lowercase host provisioned through the dynamic seam, to its issuer
    dynamic_hosts: HashMap<String, String>,
}

struct Issuer {
    entry: IssuerEntry,
    source: Source,
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
        let config_hosts = config
            .host_issuers()
            .map(|(host, _, _, issuer)| (host.to_ascii_lowercase(), issuer.to_string()))
            .collect();
        let own_certs = config
            .host_certs()
            .filter(|(_, _, cert, _)| cert.is_some())
            .map(|(host, _, _, _)| host.to_ascii_lowercase())
            .collect();

        let issuers = Self {
            state: RwLock::new(State {
                issuers: HashMap::new(),
                default: None,
                config_hosts,
                dynamic_hosts: HashMap::new(),
            }),
            fallback: OnDemand::self_signed(),
            own_certs,
            cancel,
        };
        issuers.set_issuers(config.effective_issuers())?;

        Ok(issuers)
    }

    /// Replace the issuers. An issuer with the same entry as before keeps its
    /// certs; a failed load changes nothing.
    pub(crate) fn set_issuers(&self, entries: Vec<IssuerEntry>) -> Result<(), ServerError> {
        validate_issuer_list(&entries)?;

        let current = self.state.read().issuers.clone();
        let mut issuers = HashMap::new();

        for entry in entries {
            let issuer = match current.get(&entry.name) {
                Some(issuer) if issuer.entry == entry => issuer.clone(),
                _ => Arc::new(Issuer::load(entry)?),
            };

            issuers.insert(issuer.entry.name.clone(), issuer);
        }

        let default = issuers
            .values()
            .find(|i| i.entry.default)
            .map(|i| i.entry.name.clone());

        tracing::info!(issuers = issuers.len(), default = ?default, "cert issuers set");

        let mut state = self.state.write();
        state.issuers = issuers;
        state.default = default;

        Ok(())
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
                .any(|pattern| self.own_certs.contains(pattern));

            if host.contains('*') || own_cert {
                continue;
            }

            let Some(issuer) = state.issuer_of(&host) else {
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
}

impl State {
    /// The issuer of `host`: the one of its exact entry, of its `*.domain`
    /// entry or of `*`, as the routing table picks the entry, else the default.
    fn issuer_of(&self, host: &str) -> Option<Arc<Issuer>> {
        let named = host_patterns(host)
            .iter()
            .enumerate()
            .find_map(|(i, pattern)| {
                let config = self.config_hosts.get(pattern);

                match i {
                    0 => config.or_else(|| self.dynamic_hosts.get(pattern)),
                    _ => config,
                }
            });

        let name = named.or(self.default.as_ref())?;

        match self.issuers.get(name) {
            Some(issuer) => Some(issuer.clone()),
            None => {
                tracing::warn!(host = %host, issuer = %name, "unknown cert issuer");
                self.default
                    .as_ref()
                    .and_then(|d| self.issuers.get(d))
                    .cloned()
            }
        }
    }
}

impl Issuer {
    fn load(entry: IssuerEntry) -> Result<Self, ServerError> {
        let source = match &entry.kind {
            IssuerKind::LocalCa {
                cert_file,
                key_file,
            } => Source::OnDemand(OnDemand::local_ca(cert_file, key_file)?),
            IssuerKind::SelfSigned => Source::OnDemand(OnDemand::self_signed()),
            IssuerKind::Imported {
                cert_file,
                key_file,
            } => {
                let (chain, key) = cert::load_chain(cert_file, key_file)?;
                let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
                Source::Imported(Arc::new(CertifiedKey::new(chain, signing_key)))
            }
            IssuerKind::Acme(section) => Source::Acme(Acme {
                section: section.clone(),
                names: Mutex::new(HashMap::new()),
            }),
        };

        tracing::info!(issuer = %entry.name, kind = ?entry.kind, "cert issuer loaded");

        Ok(Self { entry, source })
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

        let Some(issuer) = issuer else {
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
        issuers
            .state
            .read()
            .issuer_of(host)
            .map(|i| i.entry.name.clone())
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
}
