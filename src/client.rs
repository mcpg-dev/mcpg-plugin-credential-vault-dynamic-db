//! Minimal Vault HTTP client for
//! `dev.mcpg.credential.vault-dynamic-db`.
//!
//! Covers only the surface this plugin needs:
//! - Auth: token (no-op), AppRole login.
//! - DB engine: `POST /v1/<db_mount>/creds/<role>` (issue creds).
//! - Lease management: `PUT /v1/sys/leases/revoke` (release).
//! - Token cache: AppRole login response stored + refreshed on
//!   401 (Vault returns 403 for permission, 401 for auth-expired).

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::credential::CredentialError;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{AuthConfig, VaultConfig};

/// Vault HTTP client. Cheap to clone — internal state is Arc'd.
#[derive(Clone)]
pub(crate) struct VaultClient {
    http: HttpClient,
    base_url: String,
    namespace: Option<String>,
    db_mount: String,
    auth_state: Arc<AsyncMutex<AuthState>>,
}

struct AuthState {
    config: AuthConfig,
    /// Cached token. For token-auth this is the operator-supplied
    /// token; for AppRole this is the login response token,
    /// refreshed on 401.
    token: Option<String>,
}

impl VaultClient {
    pub fn new(cfg: &VaultConfig) -> Result<Self, CredentialError> {
        let http = HttpClient::builder()
            .connect_timeout(Duration::from_millis(cfg.connection.connect_timeout_ms))
            .timeout(Duration::from_millis(cfg.connection.operation_timeout_ms))
            .build()
            .map_err(|e| CredentialError::Backend {
                reason: format!("reqwest client init: {e}"),
            })?;
        let token = match &cfg.auth {
            AuthConfig::Token { token } => Some(token.clone()),
            AuthConfig::Approle { .. } => None,
        };
        Ok(Self {
            http,
            base_url: cfg.url.trim_end_matches('/').to_owned(),
            namespace: cfg.namespace.clone(),
            db_mount: cfg.db_mount.clone(),
            auth_state: Arc::new(AsyncMutex::new(AuthState {
                config: cfg.auth.clone(),
                token,
            })),
        })
    }

    /// Add the standard headers Vault expects: token + namespace.
    fn add_auth_headers(
        &self,
        builder: reqwest::RequestBuilder,
        token: &str,
    ) -> reqwest::RequestBuilder {
        let mut b = builder.header("X-Vault-Token", token);
        if let Some(ns) = &self.namespace {
            b = b.header("X-Vault-Namespace", ns);
        }
        b
    }

    /// Get a usable token. For token-auth this returns the cached
    /// operator-supplied value; for AppRole it logs in if needed.
    async fn current_token(&self) -> Result<String, CredentialError> {
        let mut state = self.auth_state.lock().await;
        if let Some(t) = &state.token {
            return Ok(t.clone());
        }
        match &state.config.clone() {
            AuthConfig::Token { token } => {
                state.token = Some(token.clone());
                Ok(token.clone())
            }
            AuthConfig::Approle {
                role_id,
                secret_id,
                mount_path,
            } => {
                let url = format!("{}/v1/auth/{mount_path}/login", self.base_url);
                let body = serde_json::json!({
                    "role_id": role_id,
                    "secret_id": secret_id,
                });
                let resp = self.http.post(&url).json(&body).send().await.map_err(|e| {
                    CredentialError::Backend {
                        reason: format!("approle login: {e}"),
                    }
                })?;
                let status = resp.status();
                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(CredentialError::NotAuthorized {
                        reason: format!(
                            "approle login failed ({status}): {}",
                            text.chars().take(200).collect::<String>(),
                        ),
                    });
                }
                let body: AuthLoginResponse =
                    resp.json().await.map_err(|e| CredentialError::Backend {
                        reason: format!("approle login json: {e}"),
                    })?;
                state.token = Some(body.auth.client_token.clone());
                Ok(body.auth.client_token)
            }
        }
    }

    /// Drop the cached token. Caller invokes this after a 401
    /// (auth expired) so the next call re-authenticates.
    async fn invalidate_token(&self) {
        let mut state = self.auth_state.lock().await;
        state.token = None;
    }

    /// `POST /v1/<db_mount>/creds/<role>` — issue dynamic DB
    /// credentials. On 401 transparently re-auths once.
    pub async fn issue_db_creds(&self, role: &str) -> Result<DbCreds, CredentialError> {
        let url = format!("{}/v1/{}/creds/{role}", self.base_url, self.db_mount);
        let mut last_err: Option<CredentialError> = None;
        for attempt in 0..2 {
            let token = self.current_token().await?;
            let resp = self
                .add_auth_headers(self.http.post(&url), &token)
                .send()
                .await
                .map_err(|e| CredentialError::Backend {
                    reason: format!("issue_db_creds request: {e}"),
                })?;
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                // Token expired; re-auth + retry once.
                self.invalidate_token().await;
                continue;
            }
            if status.is_success() {
                let body: DbCredsResponse =
                    resp.json().await.map_err(|e| CredentialError::Backend {
                        reason: format!("issue_db_creds json: {e}"),
                    })?;
                return Ok(DbCreds {
                    username: body.data.username,
                    password: body.data.password,
                    lease_id: body.lease_id,
                    lease_duration: body.lease_duration,
                });
            }
            // Map Vault error codes to typed CredentialError.
            let text = resp.text().await.unwrap_or_default();
            last_err = Some(map_vault_error(status, &text, role));
            break;
        }
        Err(last_err.unwrap_or(CredentialError::Backend {
            reason: "issue_db_creds: exhausted retries".into(),
        }))
    }

    /// `PUT /v1/sys/leases/revoke` with body `{"lease_id": "..."}`.
    /// Idempotent — Vault returns 204 on already-revoked.
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<(), CredentialError> {
        let url = format!("{}/v1/sys/leases/revoke", self.base_url);
        let token = self.current_token().await?;
        let body = serde_json::json!({"lease_id": lease_id});
        let resp = self
            .add_auth_headers(self.http.put(&url).json(&body), &token)
            .send()
            .await
            .map_err(|e| CredentialError::Backend {
                reason: format!("revoke_lease request: {e}"),
            })?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NO_CONTENT {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        Err(CredentialError::Backend {
            reason: format!(
                "revoke_lease failed ({status}): {}",
                text.chars().take(200).collect::<String>()
            ),
        })
    }
}

fn map_vault_error(status: reqwest::StatusCode, body_text: &str, role: &str) -> CredentialError {
    let preview: String = body_text.chars().take(200).collect();
    match status.as_u16() {
        403 => CredentialError::NotAuthorized {
            reason: format!("vault: role `{role}` denied access ({preview})"),
        },
        429 => CredentialError::Throttled {
            reason: format!("vault: rate limited ({preview})"),
        },
        400..=499 => CredentialError::Misconfigured {
            reason: format!("vault returned {status} for role `{role}`: {preview}"),
        },
        500..=599 => CredentialError::Backend {
            reason: format!("vault {status}: {preview}"),
        },
        _ => CredentialError::Backend {
            reason: format!("vault unexpected status {status}: {preview}"),
        },
    }
}

#[derive(Debug)]
pub(crate) struct DbCreds {
    pub username: String,
    pub password: String,
    pub lease_id: String,
    /// Vault's TTL in seconds.
    pub lease_duration: u64,
}

#[derive(Deserialize)]
struct AuthLoginResponse {
    auth: AuthBlock,
}

#[derive(Deserialize)]
struct AuthBlock {
    client_token: String,
}

#[derive(Deserialize)]
struct DbCredsResponse {
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    lease_duration: u64,
    data: DbCredsData,
}

#[derive(Deserialize)]
struct DbCredsData {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn map_403_to_not_authorized() {
        let err = map_vault_error(StatusCode::FORBIDDEN, "", "ro");
        assert!(matches!(err, CredentialError::NotAuthorized { .. }));
    }

    #[test]
    fn map_429_to_throttled() {
        let err = map_vault_error(StatusCode::TOO_MANY_REQUESTS, "rate limit", "ro");
        assert!(matches!(err, CredentialError::Throttled { .. }));
    }

    #[test]
    fn map_500_to_backend() {
        let err = map_vault_error(StatusCode::INTERNAL_SERVER_ERROR, "boom", "ro");
        assert!(matches!(err, CredentialError::Backend { .. }));
    }

    #[test]
    fn map_400_to_misconfigured() {
        let err = map_vault_error(StatusCode::BAD_REQUEST, "missing role", "ro");
        assert!(matches!(err, CredentialError::Misconfigured { .. }));
    }
}
