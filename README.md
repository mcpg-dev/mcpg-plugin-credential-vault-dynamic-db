# Vault Dynamic Database Credentials — `dev.mcpg.credential.vault-dynamic-db`

> class `credential_issuer` · `native` · package `mcpg-plugin-credential-vault-dynamic-db` · artifact `libmcpg_plugin_credential_vault_dynamic_db.so`

Issues per-request database credentials via Vault's database secrets engine.
Maps the caller `PluginIdentity` to a Vault role and mints a fresh
username+password with a Vault-managed lease. Reach for it for short-lived,
auto-rotated DB credentials scoped to the calling identity.

## What it does
- Authenticates to Vault (token or AppRole) and, per target, calls
  `POST /v1/<db_mount>/creds/<role>` to mint a username+password with a lease.
- Resolves the Vault role from the caller identity per `identity_mapping`:
  `static` (fixed `vault_role`), `subject_id`, `from_role` (`identity.roles[0]`),
  or `template` (`${identity.<field>}` substitution into `role_template`).
- Caps cache TTL at `min(vault_lease_duration, max_cache_ttl_ms)`. On cache
  eviction, revokes the lease (`revoke_on_evict: true`, default) or lets Vault
  auto-expire.
- Returns username/password as credential parts. Requires capability
  `network_outbound`. (Token + AppRole auth in v0.1; userpass/kubernetes
  deferred.)

## Configuration
Selected per binding via `cred://` URIs; the plugin is loaded via the top-level
`plugins:` list:

```yaml
plugins:
  - id: dev.mcpg.credential.vault-dynamic-db
    class: credential_issuer
    source: { path: ./plugins/libmcpg_plugin_credential_vault_dynamic_db.so }
    config:
      url: "https://vault.example.com:8200"
      namespace: null                  # optional Vault Enterprise namespace
      db_mount: database
      auth:
        method: token                  # "token" | "approle"
        token: "${env.VAULT_TOKEN}"
        # approle → role_id, secret_id, mount_path (default "approle")
      targets:
        orders-readonly:               # target → cred://.../orders-readonly
          identity_mapping: static     # "static" | "subject_id" | "template" | "from_role"
          vault_role: orders-readonly
          # role_template: "db-${identity.roles[0]}"   # required for "template"
          max_cache_ttl_ms: 3600000
          revoke_on_evict: true
      connection:
        connect_timeout_ms: 5000
        operation_timeout_ms: 10000
```

Top-level:

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — | Vault endpoint (`http://`/`https://`). |
| `auth` | object | — | `token { token }` or `approle { role_id, secret_id, mount_path }`. |
| `namespace` | string? | `null` | Vault Enterprise namespace (`X-Vault-Namespace`). |
| `db_mount` | string | `"database"` | Database secrets-engine mount path. |
| `targets` | map | — | Target name → config (below); non-empty. |
| `connection.connect_timeout_ms` | u64 | `5000` | Connect timeout. |
| `connection.operation_timeout_ms` | u64 | `10000` | Per-operation timeout. |

Per target (`targets.<name>`):

| Field | Type | Default | Description |
|---|---|---|---|
| `identity_mapping` | enum | `static` | `static` \| `subject_id` \| `template` \| `from_role`. |
| `vault_role` | string | `""` | Vault role; required for `static`, fallback otherwise. |
| `role_template` | string? | `null` | `${identity.<field>}` template; required for `template`. |
| `max_cache_ttl_ms` | u64 | `3600000` | Cache TTL cap (1..=86400000). |
| `revoke_on_evict` | bool | `true` | Revoke the lease on eviction vs. let Vault expire it. |

Unknown config fields are rejected; invalid config fails the plugin to load.

## Build
```bash
cargo build -p mcpg-plugin-credential-vault-dynamic-db --features cdylib-export --release   # → target/release/libmcpg_plugin_credential_vault_dynamic_db.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
