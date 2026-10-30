//! The names an issuer can sign, read from its cert: the DNS name constraints
//! of a CA, or the DNS SANs of an imported cert.

use rcgen::{GeneralSubtree, NameConstraints};

/// One DNS rule of a cert, lowercase and without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// A SAN: this name only.
    Name(String),
    /// A `*.parent` SAN: one label under `parent`.
    Wildcard(String),
    /// A name constraint: the name and the names under it (RFC 5280).
    Subtree(String),
    /// A name constraint with a leading dot: the names under it only.
    Under(String),
}

impl Rule {
    /// The length of the suffix that matches `host`, and a rank that puts an
    /// exact name before a wildcard before a subtree.
    fn score(&self, host: &str) -> Option<(usize, u8)> {
        match self {
            Rule::Name(name) => (host == name).then_some((name.len(), 3)),
            Rule::Wildcard(parent) => {
                let label = host.strip_suffix(parent)?.strip_suffix('.')?;
                (!label.is_empty() && !label.contains('.')).then_some((parent.len(), 2))
            }
            Rule::Subtree(name) => {
                let under = host.strip_suffix(name)?;
                (under.is_empty() || under.ends_with('.')).then_some((name.len(), 1))
            }
            Rule::Under(name) => {
                let label = host.strip_suffix(name)?.strip_suffix('.')?;
                (!label.is_empty()).then_some((name.len(), 1))
            }
        }
    }
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rule::Name(name) | Rule::Subtree(name) => f.write_str(name),
            Rule::Wildcard(parent) => write!(f, "*.{parent}"),
            Rule::Under(name) => write!(f, ".{name}"),
        }
    }
}

/// An issuer without a permitted DNS rule (ACME, self-signed, a CA without
/// constraints) covers no name by itself: it is only named or the default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    permitted: Vec<Rule>,
    excluded: Vec<Rule>,
}

fn clean(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Coverage {
    pub(crate) fn from_constraints(constraints: Option<&NameConstraints>) -> Self {
        let Some(constraints) = constraints else {
            return Self::default();
        };

        let rules = |subtrees: &[GeneralSubtree]| {
            subtrees
                .iter()
                .filter_map(|subtree| match subtree {
                    GeneralSubtree::DnsName(name) => Some(clean(name)),
                    _ => None,
                })
                // An empty name constrains nothing, so it covers no name either
                .filter(|name| !name.is_empty() && name != ".")
                .map(|name| match name.strip_prefix('.') {
                    Some(under) => Rule::Under(under.to_string()),
                    None => Rule::Subtree(name),
                })
                .collect()
        };

        Self {
            permitted: rules(&constraints.permitted_subtrees),
            excluded: rules(&constraints.excluded_subtrees),
        }
    }

    pub(crate) fn from_sans(cert_der: &[u8]) -> Self {
        use x509_parser::extensions::GeneralName;

        let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
            return Self::default();
        };
        let Ok(Some(sans)) = cert.subject_alternative_name() else {
            return Self::default();
        };

        let permitted = sans
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(name) => Some(clean(name)),
                _ => None,
            })
            .map(|name| match name.strip_prefix("*.") {
                Some(parent) => Rule::Wildcard(parent.to_string()),
                None => Rule::Name(name),
            })
            .collect();

        Self {
            permitted,
            excluded: Vec::new(),
        }
    }

    /// How closely the issuer covers a lowercase `host`, higher is closer;
    /// `None` when it does not cover it.
    pub(crate) fn score(&self, host: &str) -> Option<(usize, u8)> {
        if self.excluded.iter().any(|rule| rule.score(host).is_some()) {
            return None;
        }

        self.permitted
            .iter()
            .filter_map(|rule| rule.score(host))
            .max()
    }

    /// The rules as an operator reads them, e.g. `.home.lan` or `*.example.com`.
    pub(crate) fn describe(&self) -> Vec<String> {
        let permitted = self.permitted.iter().map(Rule::to_string);
        let excluded = self.excluded.iter().map(|rule| format!("not {rule}"));

        permitted.chain(excluded).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraints(permitted: &[&str], excluded: &[&str]) -> Coverage {
        let subtrees = |names: &[&str]| {
            names
                .iter()
                .map(|n| GeneralSubtree::DnsName(n.to_string()))
                .collect()
        };

        Coverage::from_constraints(Some(&NameConstraints {
            permitted_subtrees: subtrees(permitted),
            excluded_subtrees: subtrees(excluded),
        }))
    }

    #[test]
    fn a_constraint_covers_the_name_and_below_and_a_dot_only_below() {
        let ca = constraints(&["Home.LAN", ".mac-mini.local"], &[]);

        assert!(ca.score("home.lan").is_some());
        assert!(ca.score("a.b.home.lan").is_some());
        assert!(ca.score("myhome.lan").is_none());
        assert!(ca.score("mac-mini.local").is_none());
        assert!(ca.score("tuyau.mac-mini.local").is_some());
    }

    #[test]
    fn an_excluded_subtree_wins_over_a_permitted_one() {
        let ca = constraints(&["home.lan"], &["guest.home.lan"]);

        assert!(ca.score("nas.home.lan").is_some());
        assert!(ca.score("x.guest.home.lan").is_none());
    }

    #[test]
    fn a_longer_suffix_and_then_an_exact_name_score_higher() {
        let wide = constraints(&["example.com"], &[]);
        let narrow = constraints(&["lan.example.com"], &[]);

        assert!(narrow.score("a.lan.example.com") > wide.score("a.lan.example.com"));
        assert_eq!(
            Rule::Name("a.example.com".into()).score("a.example.com"),
            Some((13, 3))
        );
        assert!(
            Rule::Name("a.example.com".into()).score("a.example.com")
                > Rule::Subtree("a.example.com".into()).score("a.example.com")
        );
    }

    #[test]
    fn the_sans_of_a_cert_cover_their_names_and_one_label_under_a_wildcard() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![
            "*.example.com".to_string(),
            "example.org".to_string(),
        ])
        .unwrap()
        .self_signed(&key)
        .unwrap();
        let sans = Coverage::from_sans(cert.der());

        assert!(sans.score("a.example.com").is_some());
        assert!(sans.score("a.b.example.com").is_none());
        assert!(sans.score("example.com").is_none());
        assert!(sans.score("example.org").is_some());
        assert_eq!(sans.describe(), ["*.example.com", "example.org"]);
    }

    #[test]
    fn no_dns_rule_covers_no_name() {
        assert!(Coverage::default().score("a.example.com").is_none());
        assert!(constraints(&[""], &[]).score("a.example.com").is_none());
    }
}
