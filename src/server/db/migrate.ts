import type Database from 'better-sqlite3'

interface SqlMigration {
  id: string
  sql: string
}

const MIGRATIONS: SqlMigration[] = [
  {
    id: '0000_initial',
    sql: `
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY NOT NULL,
        user_oid TEXT NOT NULL,
        user_upn TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL,
        groups_json TEXT NOT NULL DEFAULT '[]',
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_oid ON sessions (user_oid);

      CREATE TABLE IF NOT EXISTS oidc_states (
        state TEXT PRIMARY KEY NOT NULL,
        nonce TEXT NOT NULL,
        code_verifier TEXT NOT NULL,
        cookie_binding_hash TEXT NOT NULL,
        return_to TEXT NOT NULL DEFAULT '/',
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_oidc_states_expires_at ON oidc_states (expires_at);

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY NOT NULL,
        actor_oid TEXT NOT NULL,
        actor_upn TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        ip_address TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_oid ON audit_logs (actor_oid);

      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        payload_json TEXT NOT NULL DEFAULT '{}',
        result_json TEXT,
        error TEXT,
        actor_oid TEXT NOT NULL,
        actor_upn TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        created_at INTEGER NOT NULL,
        started_at INTEGER,
        completed_at INTEGER,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_jobs_status_created_at ON jobs (status, created_at);
      CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs (created_at);

      CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY NOT NULL,
        value_json TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `,
  },
  {
    id: '0001_policy_snapshots',
    sql: `
      CREATE TABLE IF NOT EXISTS policy_snapshots (
        id TEXT PRIMARY KEY NOT NULL,
        snapshot_type TEXT NOT NULL,
        label TEXT NOT NULL,
        actor_upn TEXT NOT NULL,
        policy_count INTEGER NOT NULL,
        payload_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_policy_snapshots_type_created
        ON policy_snapshots (snapshot_type, created_at);
    `,
  },
  {
    id: '0002_cis_alerts_onboarding',
    sql: `
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
    `,
  },
  {
    id: '0003_licensing_billing',
    sql: `
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
    `,
  },
]

export function runMigrations(sqlite: Database.Database): void {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS _pocket365_migrations (
      id TEXT PRIMARY KEY NOT NULL,
      applied_at INTEGER NOT NULL
    );
  `)

  const appliedRows = sqlite
    .prepare('SELECT id FROM _pocket365_migrations')
    .all() as Array<{ id: string }>
  const appliedIds = new Set(appliedRows.map((row) => row.id))

  const insertMigration = sqlite.prepare(
    'INSERT INTO _pocket365_migrations (id, applied_at) VALUES (?, ?)',
  )

  const applyOne = sqlite.transaction((migration: SqlMigration) => {
    sqlite.exec(migration.sql)
    insertMigration.run(migration.id, Date.now())
  })

  for (const migration of MIGRATIONS) {
    if (!appliedIds.has(migration.id)) {
      applyOne(migration)
    }
  }
}
