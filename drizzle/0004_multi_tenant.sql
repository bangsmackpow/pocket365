-- Multi-tenant MSP/SaaS tables and per-session active tenant context
ALTER TABLE sessions ADD COLUMN active_tenant_id TEXT;

CREATE TABLE IF NOT EXISTS managed_tenants (
  id TEXT PRIMARY KEY NOT NULL,
  entra_tenant_id TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  primary_domain TEXT NOT NULL DEFAULT '',
  connection_mode TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  client_secret_enc TEXT,
  cert_thumbprint TEXT,
  cert_private_key_enc TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  last_health_check_at INTEGER,
  last_health_error TEXT,
  last_cis_score_pct INTEGER,
  last_mfa_coverage_pct INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_managed_tenants_entra_id
  ON managed_tenants (entra_tenant_id);

CREATE TABLE IF NOT EXISTS tenant_access (
  id TEXT PRIMARY KEY NOT NULL,
  principal TEXT NOT NULL,
  managed_tenant_id TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenant_access_principal
  ON tenant_access (principal);
