import { integer, sqliteTable, text, index } from 'drizzle-orm/sqlite-core'

export type UserRole = 'admin' | 'viewer'
export type AuditStatus = 'success' | 'failure' | 'queued'
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed'

export const sessions = sqliteTable(
  'sessions',
  {
    id: text('id').primaryKey(), // SHA-256 hash of raw session token
    userOid: text('user_oid').notNull(),
    userUpn: text('user_upn').notNull(),
    displayName: text('display_name').notNull(),
    role: text('role').$type<UserRole>().notNull(),
    groupsJson: text('groups_json').notNull().default('[]'),
    expiresAt: integer('expires_at').notNull(),
    createdAt: integer('created_at').notNull(),
    lastSeenAt: integer('last_seen_at').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
  },
  (table) => [
    index('idx_sessions_expires_at').on(table.expiresAt),
    index('idx_sessions_user_oid').on(table.userOid),
  ],
)

export const oidcStates = sqliteTable(
  'oidc_states',
  {
    state: text('state').primaryKey(),
    nonce: text('nonce').notNull(),
    codeVerifier: text('code_verifier').notNull(),
    cookieBindingHash: text('cookie_binding_hash').notNull(),
    returnTo: text('return_to').notNull().default('/'),
    expiresAt: integer('expires_at').notNull(),
    createdAt: integer('created_at').notNull(),
  },
  (table) => [index('idx_oidc_states_expires_at').on(table.expiresAt)],
)

export const auditLogs = sqliteTable(
  'audit_logs',
  {
    id: text('id').primaryKey(),
    actorOid: text('actor_oid').notNull(),
    actorUpn: text('actor_upn').notNull(),
    actorRole: text('actor_role').notNull(),
    action: text('action').notNull(),
    target: text('target').notNull(),
    status: text('status').$type<AuditStatus>().notNull(),
    detailsJson: text('details_json').notNull().default('{}'),
    ipAddress: text('ip_address'),
    createdAt: integer('created_at').notNull(),
  },
  (table) => [
    index('idx_audit_logs_created_at').on(table.createdAt),
    index('idx_audit_logs_action').on(table.action),
    index('idx_audit_logs_actor_oid').on(table.actorOid),
  ],
)

export const jobs = sqliteTable(
  'jobs',
  {
    id: text('id').primaryKey(),
    type: text('type').notNull(),
    status: text('status').$type<JobStatus>().notNull(),
    payloadJson: text('payload_json').notNull().default('{}'),
    resultJson: text('result_json'),
    error: text('error'),
    actorOid: text('actor_oid').notNull(),
    actorUpn: text('actor_upn').notNull(),
    actorRole: text('actor_role').$type<UserRole>().notNull(),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(3),
    createdAt: integer('created_at').notNull(),
    startedAt: integer('started_at'),
    completedAt: integer('completed_at'),
    updatedAt: integer('updated_at').notNull(),
  },
  (table) => [
    index('idx_jobs_status_created_at').on(table.status, table.createdAt),
    index('idx_jobs_created_at').on(table.createdAt),
  ],
)

export const appSettings = sqliteTable('app_settings', {
  key: text('key').primaryKey(),
  valueJson: text('value_json').notNull(),
  updatedBy: text('updated_by').notNull(),
  updatedAt: integer('updated_at').notNull(),
})

export type SessionRow = typeof sessions.$inferSelect
export type AuditLogRow = typeof auditLogs.$inferSelect
export type JobRow = typeof jobs.$inferSelect
export type AppSettingRow = typeof appSettings.$inferSelect
