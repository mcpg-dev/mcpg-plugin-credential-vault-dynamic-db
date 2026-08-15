//! Operator-supplied configuration schema for
//! `dev.mcpg.credential.vault-dynamic-db`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// Vault HTTP endpoint, e.g. `https://vault.example.com:8200`.
    pub url: String,

    /// Vault auth method. Supports token + approle; userpass
    /// + kubernetes deferred.
    pub auth: AuthConfig,

    /// Optional Enterprise namespace (`X-Vault-Namespace` header).
    #[serde(default)]
    pub namespace: Option<String>,

    /// DB secrets-engine mount path. Default `database/`.
    #[serde(default = "default_db_mount")]
    pub db_mount: String,

    /// Per-target role mapping. At least one target required.
    pub targets: BTreeMap<String, TargetConfig>,

    /// Connection knobs.
    #[serde(default)]
    pub connection: ConnectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthConfig {
    Token {
        token: String,
    },
    Approle {
        role_id: String,
        secret_id: String,
        /// Mount path for the AppRole auth method. Default
        /// `approle`.
        #[serde(default = "default_approle_mount")]
        mount_path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Vault role name. Required when `identity_mapping == "static"`.
    /// For `template` mode, this is the fallback when template
    /// substitution returns empty.
    #[serde(default)]
    pub vault_role: String,

    #[serde(default)]
    pub identity_mapping: IdentityMapping,

    /// Required when `identity_mapping == "template"`. Substitution
    /// syntax: `${identity.<field>}` — fields:
    /// `subject_id`, `kind`, `trust_level`, `auth_provider`,
    /// `roles[N]`, `groups[N]`, `scopes[N]`, `attributes.<key>`.
    #[serde(default)]
    pub role_template: Option<String>,

    /// Cap on the cache TTL for this target. The plugin returns
    /// `min(vault_lease_duration, max_cache_ttl_ms)` so the
    /// gateway's per-target cache won't outlive the Vault lease
    /// even if Vault hands back a long one.
    #[serde(default = "default_max_cache_ttl_ms")]
    pub max_cache_ttl_ms: u64,

    /// Whether to revoke explicitly on cache eviction. Default
    /// true — keeps DB account count low. False = let Vault
    /// auto-expire at lease TTL (~minimal API load, but accounts
    /// linger).
    #[serde(default = "default_true")]
    pub revoke_on_evict: bool,

    /// Optional allowlist of Vault role names this target may issue.
    /// When `Some`, an identity-derived role (subject_id /
    /// first-role / template output) MUST appear in this list or the
    /// request is refused — bounding which roles a caller can select
    /// even if the upstream identity is spoofable. When `None` (the
    /// default) no allowlist is applied. Static mode is unaffected (the
    /// role is operator-fixed). Entries are validated to the Vault
    /// role-name charset at config load.
    #[serde(default)]
    pub allowed_roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMapping {
    /// Always use `target.vault_role`. Default.
    #[default]
    Static,
    /// Use `identity.subject_id` directly as the Vault role.
    /// Operator must pre-create matching Vault roles per
    /// principal.
    SubjectId,
    /// Substitute identity fields into `target.role_template`.
    Template,
    /// Use `identity.roles[0]` as the Vault role.
    FromRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            operation_timeout_ms: default_operation_timeout_ms(),
        }
    }
}

fn default_db_mount() -> String {
    "database".into()
}
fn default_approle_mount() -> String {
    "approle".into()
}
fn default_max_cache_ttl_ms() -> u64 {
    3600000
}
fn default_true() -> bool {
    true
}
fn default_connect_timeout_ms() -> u64 {
    5000
}
fn default_operation_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid credential.vault-dynamic-db config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("credential.vault-dynamic-db: url is empty")]
    EmptyUrl,
    #[error("credential.vault-dynamic-db: url must start with http:// or https://")]
    InvalidUrlScheme,
    #[error("credential.vault-dynamic-db: db_mount is empty")]
    EmptyDbMount,
    #[error("credential.vault-dynamic-db: targets must be non-empty")]
    EmptyTargets,
    #[error(
        "credential.vault-dynamic-db: target `{name}` has identity_mapping=static but vault_role is empty"
    )]
    StaticTargetMissingRole { name: String },
    #[error(
        "credential.vault-dynamic-db: target `{name}` has identity_mapping=template but role_template is missing"
    )]
    TemplateTargetMissingTemplate { name: String },
    #[error(
        "credential.vault-dynamic-db: target `{name}` has max_cache_ttl_ms={ttl}; must be 1..=86_400_000 (1 ms to 1 day)"
    )]
    InvalidMaxCacheTtl { name: String, ttl: u64 },
    #[error("credential.vault-dynamic-db: auth.token is empty")]
    EmptyToken,
    #[error("credential.vault-dynamic-db: auth.role_id is empty")]
    EmptyRoleId,
    #[error("credential.vault-dynamic-db: auth.secret_id is empty")]
    EmptySecretId,
    #[error("credential.vault-dynamic-db: auth.mount_path is empty")]
    EmptyApproleMountPath,
    #[error(
        "credential.vault-dynamic-db: target `{name}` allowed_roles entry `{role}` is not a valid \
         Vault role name (allowed: A-Z a-z 0-9 _ -, 1..=128 chars)"
    )]
    InvalidAllowedRole { name: String, role: String },
}

impl VaultConfig {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.url.trim().is_empty() {
            return Err(ConfigError::EmptyUrl);
        }
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConfigError::InvalidUrlScheme);
        }
        if self.db_mount.trim().is_empty() {
            return Err(ConfigError::EmptyDbMount);
        }
        if self.targets.is_empty() {
            return Err(ConfigError::EmptyTargets);
        }
        match &self.auth {
            AuthConfig::Token { token } if token.is_empty() => {
                return Err(ConfigError::EmptyToken);
            }
            AuthConfig::Approle {
                role_id,
                secret_id,
                mount_path,
            } => {
                if role_id.is_empty() {
                    return Err(ConfigError::EmptyRoleId);
                }
                if secret_id.is_empty() {
                    return Err(ConfigError::EmptySecretId);
                }
                if mount_path.trim().is_empty() {
                    return Err(ConfigError::EmptyApproleMountPath);
                }
            }
            _ => {}
        }
        for (name, target) in &self.targets {
            match target.identity_mapping {
                IdentityMapping::Static => {
                    if target.vault_role.is_empty() {
                        return Err(ConfigError::StaticTargetMissingRole { name: name.clone() });
                    }
                }
                IdentityMapping::Template => {
                    if target
                        .role_template
                        .as_deref()
                        .map(str::is_empty)
                        .unwrap_or(true)
                    {
                        return Err(ConfigError::TemplateTargetMissingTemplate {
                            name: name.clone(),
                        });
                    }
                }
                IdentityMapping::SubjectId | IdentityMapping::FromRole => {
                    // Both fall back to `vault_role` when the
                    // identity-derived value is empty; OK for it
                    // to be empty (the runtime returns
                    // NotAuthorized in that case).
                }
            }
            if target.max_cache_ttl_ms == 0 || target.max_cache_ttl_ms > 86_400_000 {
                return Err(ConfigError::InvalidMaxCacheTtl {
                    name: name.clone(),
                    ttl: target.max_cache_ttl_ms,
                });
            }
            if let Some(allow) = &target.allowed_roles {
                for role in allow {
                    if !crate::identity_mapping::is_valid_role_name(role) {
                        return Err(ConfigError::InvalidAllowedRole {
                            name: name.clone(),
                            role: role.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal() -> serde_json::Value {
        json!({
            "url": "https://vault.example.com:8200",
            "auth": {"method": "token", "token": "s.abc123"},
            "targets": {
                "orders-readonly": {
                    "vault_role": "orders-readonly"
                }
            }
        })
    }

    #[test]
    fn parses_minimal() {
        let cfg = VaultConfig::parse(&minimal().to_string()).unwrap();
        assert_eq!(cfg.db_mount, "database");
        assert!(cfg.targets.contains_key("orders-readonly"));
    }

    #[test]
    fn rejects_empty_url() {
        let mut v = minimal();
        v["url"] = json!("");
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyUrl
        ));
    }

    #[test]
    fn rejects_unknown_url_scheme() {
        let mut v = minimal();
        v["url"] = json!("file:///vault");
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidUrlScheme
        ));
    }

    #[test]
    fn rejects_empty_token() {
        let mut v = minimal();
        v["auth"] = json!({"method": "token", "token": ""});
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::EmptyToken
        ));
    }

    #[test]
    fn approle_auth_roundtrip() {
        let v = json!({
            "url": "https://vault.example.com:8200",
            "auth": {
                "method": "approle",
                "role_id": "rid-abc",
                "secret_id": "sid-xyz"
            },
            "targets": {
                "x": {"vault_role": "x"}
            }
        });
        let cfg = VaultConfig::parse(&v.to_string()).unwrap();
        match cfg.auth {
            AuthConfig::Approle {
                role_id,
                secret_id,
                mount_path,
            } => {
                assert_eq!(role_id, "rid-abc");
                assert_eq!(secret_id, "sid-xyz");
                assert_eq!(mount_path, "approle");
            }
            _ => panic!("expected Approle"),
        }
    }

    #[test]
    fn rejects_static_without_vault_role() {
        let mut v = minimal();
        v["targets"]["orders-readonly"]["vault_role"] = json!("");
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::StaticTargetMissingRole { .. }
        ));
    }

    #[test]
    fn rejects_template_without_template() {
        let mut v = minimal();
        v["targets"]["orders-readonly"] = json!({
            "vault_role": "fallback",
            "identity_mapping": "template"
        });
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::TemplateTargetMissingTemplate { .. }
        ));
    }

    #[test]
    fn rejects_zero_ttl() {
        let mut v = minimal();
        v["targets"]["orders-readonly"]["max_cache_ttl_ms"] = json!(0);
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMaxCacheTtl { .. }
        ));
    }

    #[test]
    fn rejects_oversized_ttl() {
        let mut v = minimal();
        v["targets"]["orders-readonly"]["max_cache_ttl_ms"] = json!(86_400_001);
        assert!(matches!(
            VaultConfig::parse(&v.to_string()).unwrap_err(),
            ConfigError::InvalidMaxCacheTtl { .. }
        ));
    }
}
