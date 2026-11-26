-- Commercial tiering, offline Ed25519 license state, and Stripe subscription sync
CREATE TABLE IF NOT EXISTS license_state (
  id TEXT PRIMARY KEY NOT NULL,
  source TEXT NOT NULL,
  tier TEXT NOT NULL,
  licensee TEXT NOT NULL DEFAULT 'Self-Hosted',
  license_key_enc TEXT,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  max_tenants INTEGER NOT NULL DEFAULT 1,
  max_users INTEGER NOT NULL DEFAULT 50,
  expires_at INTEGER,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
