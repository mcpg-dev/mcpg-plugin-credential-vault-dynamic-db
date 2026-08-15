//! `dev.mcpg.credential.vault-dynamic-db` — `credential_issuer` plugin.
//!
//! Issues per-request database credentials via Vault's database
//! secrets engine. Operator pre-creates Vault DB roles bound to
//! per-tenant DB users + permissions; this plugin maps caller
//! `PluginIdentity` to a Vault role per operator-configurable
//! rules and calls `POST /v1/database/creds/<role>`. The gateway's
//! per-(identity, plugin, target) cache holds the credential for
//! `min(vault_lease_duration_secs, max_cache_ttl_ms / 1000)` (floored
//! at 1s) so steady-state issuance load stays low.
//!
//! # Scope
//!
//! - **Auth methods**: token, AppRole. Userpass + Kubernetes
//!   auth deferred.
//! - **Identity mapping**: static, subject_id, template, from_role.
//! - **Issue + revoke**: full DB-engine surface.
//! - **Token refresh**: AppRole login response is cached;
//!   re-authenticated transparently on Vault 401.
//! - **Connection knobs**: connect_timeout_ms +
//!   operation_timeout_ms.

mod client;
mod config;
mod identity_mapping;

use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginManifest};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncCredentialIssuer;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{
    AuthConfig, ConfigError, ConnectionConfig, IdentityMapping, TargetConfig, VaultConfig,
};

const PLUGIN_ID: &str = "dev.mcpg.credential.vault-dynamic-db";

pub struct VaultDynamicDbPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    config: VaultConfig,
    client: client::VaultClient,
    runtime: Runtime,
}

impl VaultDynamicDbPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = VaultConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "vault-dynamic-db: config parse failed; refusing to register"
            );
            panic!(
                "vault-dynamic-db config parse failed: {err}. A misconfigured \
                 credential issuer is a security hole; refusing to load."
            )
        });
        Self::from_validated_config(cfg)
    }

    fn from_validated_config(cfg: VaultConfig) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("vault-dynamic-db: failed to build tokio runtime");
        let client = client::VaultClient::new(&cfg)
            .unwrap_or_else(|err| panic!("vault-dynamic-db: HTTP client init failed: {err}"));
        tracing::info!(
            plugin_id = PLUGIN_ID,
            url = %cfg.url,
            db_mount = %cfg.db_mount,
            target_count = cfg.targets.len(),
            "vault-dynamic-db: configured"
        );
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Vault Dynamic Database Credentials".into(),
                    plugin_class: PluginClass::CredentialIssuer,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config: cfg,
                client,
                runtime,
            }),
        }
    }
}

async fn issue_inner(
    inner: &Inner,
    identity: &PluginIdentity,
    target: &str,
) -> Result<IssuedCredential, CredentialError> {
    let target_cfg =
        inner
            .config
            .targets
            .get(target)
            .ok_or_else(|| CredentialError::Misconfigured {
                reason: format!("unknown target: {target}"),
            })?;
    let role = match identity_mapping::resolve_role(identity, target_cfg) {
        identity_mapping::Resolution::Role {
            role,
            identity_derived,
        } => {
            // A role driven by caller-controlled identity
            // (subject_id / first-role / template) must come from a
            // Verified principal. Header-asserted / unauthenticated
            // identities are spoofable (e.g. the `x-mcpg-subject-id`
            // header) and must not steer which Vault role — and thus
            // which DB grants — the caller receives. Static and
            // fallback roles are operator-fixed and exempt.
            if identity_derived && identity.trust_level != "verified" {
                metrics::counter!(
                    "mcpg_vault_dynamic_db_issue_total",
                    "target" => target.to_owned(),
                    "result" => "untrusted_identity",
                )
                .increment(1);
                return Err(CredentialError::NotAuthorized {
                    reason: format!(
                        "identity-derived Vault role requires Verified trust; caller trust is `{}`",
                        identity.trust_level
                    ),
                });
            }
            // The role is interpolated straight into the Vault
            // API path (`/v1/<db_mount>/creds/<role>`); reject anything
            // outside the Vault role-name charset so a crafted identity
            // can't traverse to another endpoint (path injection).
            if !identity_mapping::is_valid_role_name(&role) {
                metrics::counter!(
                    "mcpg_vault_dynamic_db_issue_total",
                    "target" => target.to_owned(),
                    "result" => "invalid_role_name",
                )
                .increment(1);
                return Err(CredentialError::NotAuthorized {
                    reason: "resolved Vault role name is not path-safe (allowed: A-Z a-z 0-9 _ -)"
                        .into(),
                });
            }
            // Optional per-target allowlist bounds which roles
            // this target may ever issue.
            if let Some(allow) = &target_cfg.allowed_roles
                && !allow.iter().any(|a| a == &role)
            {
                metrics::counter!(
                    "mcpg_vault_dynamic_db_issue_total",
                    "target" => target.to_owned(),
                    "result" => "role_not_allowed",
                )
                .increment(1);
                return Err(CredentialError::NotAuthorized {
                    reason: "resolved Vault role is not in this target's allowed_roles".into(),
                });
            }
            role
        }
        identity_mapping::Resolution::EmptyDerived { reason } => {
            return Err(CredentialError::NotAuthorized { reason });
        }
        identity_mapping::Resolution::SubstitutionFailed { field } => {
            return Err(CredentialError::NotAuthorized {
                reason: format!(
                    "identity template substitution failed: field `{field}` is None or out-of-bounds"
                ),
            });
        }
    };
    let started = std::time::Instant::now();
    let creds = inner.client.issue_db_creds(&role).await?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    metrics::histogram!(
        "mcpg_vault_dynamic_db_issue_latency_ms",
        "target" => target.to_owned(),
    )
    .record(elapsed_ms as f64);
    metrics::counter!(
        "mcpg_vault_dynamic_db_issue_total",
        "target" => target.to_owned(),
        "result" => "ok",
    )
    .increment(1);
    let ttl = cap_ttl_seconds(creds.lease_duration, target_cfg.max_cache_ttl_ms);
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("vault.role".to_string(), role.clone());
    metadata.insert("vault.mount".to_string(), inner.config.db_mount.clone());
    Ok(IssuedCredential {
        value: None,
        parts: [
            ("username".to_string(), creds.username),
            ("password".to_string(), creds.password),
        ]
        .into_iter()
        .collect(),
        ttl_seconds: ttl,
        lease_id: Some(creds.lease_id),
        issued_at: now_rfc3339(),
        metadata,
    })
}

async fn revoke_inner(inner: &Inner, lease_id: &str) -> Result<(), CredentialError> {
    inner.client.revoke_lease(lease_id).await?;
    metrics::counter!("mcpg_vault_dynamic_db_revoke_total").increment(1);
    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Cap the cached credential TTL (seconds) at the operator's millisecond
/// limit. `max_cache_ttl_ms` is in milliseconds while the Vault lease and
/// the host cache both work in seconds, so convert before clamping, with a
/// 1-second floor so a sub-second cap never yields a 0s TTL (instant expiry).
fn cap_ttl_seconds(lease_secs: u64, max_cache_ttl_ms: u64) -> u64 {
    (max_cache_ttl_ms / 1000).max(1).min(lease_secs)
}

#[async_trait]
impl CredentialIssuer for VaultDynamicDbPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        issue_inner(&self.inner, identity, target).await
    }

    async fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
        revoke_inner(&self.inner, lease_id).await
    }
}

impl SyncCredentialIssuer for VaultDynamicDbPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        _config: &Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let inner = Arc::clone(&self.inner);
        let identity = identity.clone();
        let target = target.to_owned();
        self.inner
            .runtime
            .block_on(async move { issue_inner(&inner, &identity, &target).await })
    }

    fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
        let inner = Arc::clone(&self.inner);
        let lease_id = lease_id.to_owned();
        self.inner
            .runtime
            .block_on(async move { revoke_inner(&inner, &lease_id).await })
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        credential_issuer as entity {
            inner_name: "",
            plugin_type: VaultDynamicDbPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> VaultDynamicDbPlugin {
                VaultDynamicDbPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cap_ttl_clamps_long_lease() {
        // 60_000 ms cap clamps a 3600 s lease to 60 s.
        assert_eq!(cap_ttl_seconds(3600, 60_000), 60);
    }

    #[test]
    fn cap_ttl_uses_lease_when_below_cap() {
        assert_eq!(cap_ttl_seconds(45, 3_600_000), 45);
    }

    #[test]
    fn cap_ttl_sub_second_cap_floors_to_one() {
        assert_eq!(cap_ttl_seconds(3600, 500), 1);
    }

    #[test]
    fn cap_ttl_equal_units_is_noop() {
        assert_eq!(cap_ttl_seconds(3600, 3_600_000), 3600);
    }

    fn minimal_cfg() -> VaultConfig {
        VaultConfig::parse(
            &json!({
                "url": "https://vault.example.com:8200",
                "auth": {"method": "token", "token": "s.abc123"},
                "targets": {
                    "orders-readonly": {
                        "vault_role": "orders-readonly"
                    }
                }
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn from_config_json_succeeds_with_minimal_token_config() {
        let plugin = VaultDynamicDbPlugin::from_validated_config(minimal_cfg());
        assert_eq!(plugin.inner.manifest.id, PLUGIN_ID);
        assert_eq!(plugin.inner.config.targets.len(), 1);
    }

    #[test]
    #[should_panic(expected = "vault-dynamic-db config parse failed")]
    fn malformed_config_panics_at_construction() {
        VaultDynamicDbPlugin::from_config_json("{ not json");
    }

    #[test]
    #[should_panic(expected = "vault-dynamic-db config parse failed")]
    fn empty_targets_panics_at_construction() {
        let bad = json!({
            "url": "https://x:8200",
            "auth": {"method": "token", "token": "t"},
            "targets": {}
        });
        VaultDynamicDbPlugin::from_config_json(&bad.to_string());
    }

    // ----- identity-derived role guards (return before any
    // network call, so these are deterministic + offline) -----

    fn identity(trust: &str, subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust.to_owned(),
            trust_level: trust.to_owned(),
            subject_id: Some(subject.to_owned()),
            auth_provider: Some("okta".into()),
            issuer: Some("https://okta.example.com".into()),
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        }
    }

    fn plugin_with_subject_target(allowed_roles: Option<Vec<&str>>) -> VaultDynamicDbPlugin {
        let mut target = json!({
            "vault_role": "fallback",
            "identity_mapping": "subject_id"
        });
        if let Some(allow) = allowed_roles {
            target["allowed_roles"] = json!(allow);
        }
        let cfg = json!({
            "url": "https://vault.invalid:8200",
            "auth": {"method": "token", "token": "t"},
            "targets": { "t": target }
        });
        VaultDynamicDbPlugin::from_config_json(&cfg.to_string())
    }

    #[test]
    fn issue_rejects_identity_derived_role_from_unverified_caller() {
        let plugin = plugin_with_subject_target(None);
        // header_asserted is spoofable → an identity-derived role must be
        // refused before any Vault call.
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("header_asserted", "alice"),
            "t",
            &Value::Null,
        )
        .expect_err("unverified identity-derived role must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("Verified trust")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_path_injecting_role_name() {
        let plugin = plugin_with_subject_target(None);
        // Verified caller, but the subject (used as the role) contains a
        // path separator → path-injection guard refuses it.
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("verified", "../../sys/policies/acl"),
            "t",
            &Value::Null,
        )
        .expect_err("path-injecting role must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("path-safe")),
            "{err:?}"
        );
    }

    #[test]
    fn issue_rejects_role_outside_allowlist() {
        let plugin = plugin_with_subject_target(Some(vec!["orders-ro"]));
        // Verified caller, valid charset, but the resolved role isn't in
        // the target's allowed_roles.
        let err = SyncCredentialIssuer::issue(
            &plugin,
            &identity("verified", "billing-admin"),
            "t",
            &Value::Null,
        )
        .expect_err("role outside allowlist must be refused");
        assert!(
            matches!(err, CredentialError::NotAuthorized { ref reason } if reason.contains("allowed_roles")),
            "{err:?}"
        );
    }
}
