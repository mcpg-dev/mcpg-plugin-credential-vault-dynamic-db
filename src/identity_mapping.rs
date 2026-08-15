//! Identity → Vault role resolution for
//! `dev.mcpg.credential.vault-dynamic-db`.

use mcpg_plugin_protocol::types::PluginIdentity;

use crate::config::{IdentityMapping, TargetConfig};

/// Resolution outcome. The error variants surface as
/// `CredentialError::NotAuthorized` so the caller (the gateway's
/// resolver) treats "this identity can't get a credential" as an
/// authorization failure rather than a backend error.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// Use this Vault role. `identity_derived` is true when the role
    /// value came from caller-controlled identity (subject_id /
    /// first-role / template substitution) rather than the operator's
    /// static `vault_role`. The caller (`issue_inner`) gates
    /// identity-derived roles on Verified trust.
    Role {
        role: String,
        identity_derived: bool,
    },
    /// Identity-derived value was empty (e.g. caller has no
    /// roles when `from_role` is configured) AND no static
    /// fallback. Maps to NotAuthorized.
    EmptyDerived { reason: String },
    /// Template referenced a field that's None or out-of-bounds.
    /// Maps to NotAuthorized.
    SubstitutionFailed { field: String },
}

/// A Vault role name is path-safe only if it is non-empty and contains
/// solely `[A-Za-z0-9_-]`. The resolved role is interpolated
/// straight into `/v1/<db_mount>/creds/<role>`, so a `/` or `..` would
/// let a caller-controlled identity traverse to a different Vault API
/// path. Vault role names are themselves alphanumeric + `-`/`_`, so this
/// rejects nothing legitimate.
pub(crate) fn is_valid_role_name(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 128
        && role
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn resolve_role(identity: &PluginIdentity, target: &TargetConfig) -> Resolution {
    match target.identity_mapping {
        IdentityMapping::Static => Resolution::Role {
            role: target.vault_role.clone(),
            identity_derived: false,
        },
        IdentityMapping::SubjectId => match identity.subject_id.as_deref() {
            Some(s) if !s.is_empty() => Resolution::Role {
                role: s.to_owned(),
                identity_derived: true,
            },
            _ if !target.vault_role.is_empty() => Resolution::Role {
                role: target.vault_role.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no subject_id and no static fallback".into(),
            },
        },
        IdentityMapping::FromRole => match identity.roles.first() {
            Some(r) if !r.is_empty() => Resolution::Role {
                role: r.clone(),
                identity_derived: true,
            },
            _ if !target.vault_role.is_empty() => Resolution::Role {
                role: target.vault_role.clone(),
                identity_derived: false,
            },
            _ => Resolution::EmptyDerived {
                reason: "identity has no roles and no static fallback".into(),
            },
        },
        IdentityMapping::Template => {
            // Validation guarantees role_template is Some + non-empty
            // for Template mode.
            let template = target.role_template.as_deref().unwrap_or("");
            substitute(template, identity)
        }
    }
}

/// Substitute `${identity.<field>}` placeholders. Supported fields:
///
/// - `subject_id`, `kind`, `trust_level`, `auth_provider`
/// - `roles[N]`, `groups[N]`, `scopes[N]` — index into the
///   corresponding Vec.
/// - `attributes.<key>` — index into the BTreeMap.
///
/// Any reference to a None / empty / out-of-bounds field returns
/// `SubstitutionFailed { field }` so the caller knows precisely
/// which placeholder failed.
fn substitute(template: &str, identity: &PluginIdentity) -> Resolution {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut placeholder = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                placeholder.push(ch);
            }
            if !closed {
                return Resolution::SubstitutionFailed {
                    field: format!("unterminated placeholder `${{{placeholder}`"),
                };
            }
            let field = placeholder
                .strip_prefix("identity.")
                .unwrap_or(placeholder.as_str());
            match resolve_field(field, identity) {
                Some(s) if !s.is_empty() => out.push_str(&s),
                _ => {
                    return Resolution::SubstitutionFailed {
                        field: field.to_owned(),
                    };
                }
            }
        } else {
            out.push(c);
        }
    }
    if out.is_empty() {
        Resolution::EmptyDerived {
            reason: "template substitution produced empty role name".into(),
        }
    } else {
        // Template output folds in caller-controlled identity fields, so
        // the resulting role is identity-derived (subject to the trust gate).
        Resolution::Role {
            role: out,
            identity_derived: true,
        }
    }
}

fn resolve_field(field: &str, identity: &PluginIdentity) -> Option<String> {
    match field {
        "subject_id" => identity.subject_id.clone(),
        "kind" => Some(identity.kind.clone()),
        "trust_level" => Some(identity.trust_level.clone()),
        "auth_provider" => identity.auth_provider.clone(),
        f if f.starts_with("attributes.") => {
            let key = &f["attributes.".len()..];
            identity.attributes.get(key).cloned()
        }
        f if let Some(idx) = parse_indexed(f, "roles") => identity.roles.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "groups") => identity.groups.get(idx).cloned(),
        f if let Some(idx) = parse_indexed(f, "scopes") => identity.scopes.get(idx).cloned(),
        _ => None,
    }
}

/// Parse `<name>[<idx>]` → `Some(idx)` when name matches.
fn parse_indexed(field: &str, name: &str) -> Option<usize> {
    let prefix = format!("{name}[");
    let rest = field.strip_prefix(&prefix)?;
    let inner = rest.strip_suffix(']')?;
    inner.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::types::PluginIdentity;
    use std::collections::BTreeMap;

    fn ident(subject: Option<&str>) -> PluginIdentity {
        let mut attrs = BTreeMap::new();
        attrs.insert("department".into(), "platform".into());
        attrs.insert("team".into(), "secops".into());
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: subject.map(|s| s.to_owned()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec!["admin".into(), "auditor".into()],
            groups: vec!["sec".into()],
            scopes: vec![],
            attributes: attrs,
        }
    }

    fn target(mapping: IdentityMapping, vault_role: &str, template: Option<&str>) -> TargetConfig {
        TargetConfig {
            vault_role: vault_role.into(),
            identity_mapping: mapping,
            role_template: template.map(|s| s.to_owned()),
            max_cache_ttl_ms: 60,
            revoke_on_evict: true,
            allowed_roles: None,
        }
    }

    /// Assert `r` is `Role { role, identity_derived }`.
    fn assert_role(r: &Resolution, want_role: &str, want_derived: bool) {
        match r {
            Resolution::Role {
                role,
                identity_derived,
            } => {
                assert_eq!(role, want_role, "role");
                assert_eq!(*identity_derived, want_derived, "identity_derived");
            }
            other => panic!("expected Role, got {other:?}"),
        }
    }

    #[test]
    fn static_returns_configured_role() {
        let r = resolve_role(
            &ident(Some("alice")),
            &target(IdentityMapping::Static, "ro", None),
        );
        assert_role(&r, "ro", false);
    }

    #[test]
    fn subject_id_returns_caller_subject() {
        let r = resolve_role(
            &ident(Some("alice")),
            &target(IdentityMapping::SubjectId, "fallback", None),
        );
        assert_role(&r, "alice", true);
    }

    #[test]
    fn subject_id_falls_back_when_anonymous() {
        let r = resolve_role(
            &ident(None),
            &target(IdentityMapping::SubjectId, "fallback", None),
        );
        // Fallback to the operator's static role is NOT identity-derived.
        assert_role(&r, "fallback", false);
    }

    #[test]
    fn subject_id_empty_derived_when_no_fallback() {
        let r = resolve_role(&ident(None), &target(IdentityMapping::SubjectId, "", None));
        assert!(matches!(r, Resolution::EmptyDerived { .. }));
    }

    #[test]
    fn from_role_returns_first() {
        let r = resolve_role(
            &ident(Some("alice")),
            &target(IdentityMapping::FromRole, "fallback", None),
        );
        assert_role(&r, "admin", true);
    }

    #[test]
    fn from_role_falls_back_when_empty() {
        let mut id = ident(Some("alice"));
        id.roles.clear();
        let r = resolve_role(&id, &target(IdentityMapping::FromRole, "fallback", None));
        assert_role(&r, "fallback", false);
    }

    #[test]
    fn template_substitutes_attribute() {
        let r = resolve_role(
            &ident(Some("alice")),
            &target(
                IdentityMapping::Template,
                "",
                Some("${identity.attributes.department}-readonly"),
            ),
        );
        assert_role(&r, "platform-readonly", true);
    }

    #[test]
    fn template_substitutes_indexed_role() {
        let r = resolve_role(
            &ident(Some("alice")),
            &target(
                IdentityMapping::Template,
                "",
                Some("${identity.roles[1]}-rw"),
            ),
        );
        assert_role(&r, "auditor-rw", true);
    }

    #[test]
    fn role_name_validation_rejects_path_separators() {
        assert!(is_valid_role_name("orders-readonly"));
        assert!(is_valid_role_name("svc_acct_1"));
        assert!(!is_valid_role_name(""));
        assert!(!is_valid_role_name("../../sys/policies"));
        assert!(!is_valid_role_name("a/b"));
        assert!(!is_valid_role_name("role with space"));
        assert!(!is_valid_role_name(&"x".repeat(129)));
    }

    #[test]
    fn template_substitution_failure_surfaces_field_name() {
        let r = resolve_role(
            &ident(None),
            &target(
                IdentityMapping::Template,
                "",
                Some("${identity.subject_id}-ro"),
            ),
        );
        match r {
            Resolution::SubstitutionFailed { field } => {
                assert_eq!(field, "subject_id");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn template_unterminated_placeholder_errors() {
        let r = resolve_role(
            &ident(Some("a")),
            &target(IdentityMapping::Template, "", Some("${identity.subject_id")),
        );
        assert!(matches!(r, Resolution::SubstitutionFailed { .. }));
    }
}
