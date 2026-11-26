CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  home_entra_tenant_id TEXT,
  owner_upn TEXT NOT NULL,
  plan_tier TEXT NOT NULL DEFAULT 'community',
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  subscription_status TEXT NOT NULL DEFAULT 'inactive',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_organizations_home_tenant
  ON organizations (home_entra_tenant_id);
CREATE INDEX IF NOT EXISTS idx_organizations_stripe_customer
  ON organizations (stripe_customer_id);

INSERT OR IGNORE INTO organizations (
  id, name, slug, home_entra_tenant_id, owner_upn, plan_tier, subscription_status, created_at, updated_at
) VALUES (
  'default', 'Default Organization', 'default', NULL, 'system', 'community', 'inactive', 0, 0
);

ALTER TABLE sessions ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions (organization_id);

ALTER TABLE audit_logs ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs (organization_id, created_at);

ALTER TABLE jobs ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_jobs_org ON jobs (organization_id, created_at);

ALTER TABLE policy_snapshots ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_policy_snapshots_org ON policy_snapshots (organization_id, snapshot_type, created_at);

ALTER TABLE cis_snapshots ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_cis_snapshots_org ON cis_snapshots (organization_id, created_at);

ALTER TABLE alert_webhooks ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_alert_webhooks_org ON alert_webhooks (organization_id);

ALTER TABLE alert_events ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_alert_events_org ON alert_events (organization_id, created_at);

ALTER TABLE onboarding_templates ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_onboarding_templates_org ON onboarding_templates (organization_id);

ALTER TABLE license_state ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_license_state_org ON license_state (organization_id);

ALTER TABLE managed_tenants ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_managed_tenants_org ON managed_tenants (organization_id, entra_tenant_id);

ALTER TABLE tenant_access ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_tenant_access_org ON tenant_access (organization_id, principal);
