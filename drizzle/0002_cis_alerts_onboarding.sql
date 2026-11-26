-- CIS snapshots, automated alerting webhooks/events, and onboarding templates
CREATE TABLE IF NOT EXISTS cis_snapshots (
  id TEXT PRIMARY KEY NOT NULL,
  actor_upn TEXT NOT NULL,
  score_pct INTEGER NOT NULL,
  passed INTEGER NOT NULL,
  failed INTEGER NOT NULL,
  warned INTEGER NOT NULL,
  unavailable INTEGER NOT NULL,
  checks_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cis_snapshots_created
  ON cis_snapshots (created_at);

CREATE TABLE IF NOT EXISTS alert_webhooks (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  provider TEXT NOT NULL,
  url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_events (
  id TEXT PRIMARY KEY NOT NULL,
  rule_key TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  delivery_status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_events_created
  ON alert_events (created_at);
CREATE INDEX IF NOT EXISTS idx_alert_events_dedupe
  ON alert_events (dedupe_key, created_at);

CREATE TABLE IF NOT EXISTS onboarding_templates (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  job_title TEXT NOT NULL DEFAULT '',
  office_location TEXT NOT NULL DEFAULT '',
  usage_location TEXT NOT NULL DEFAULT 'US',
  sku_ids_json TEXT NOT NULL DEFAULT '[]',
  group_ids_json TEXT NOT NULL DEFAULT '[]',
  issue_tap INTEGER NOT NULL DEFAULT 0,
  force_password_change INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
