import crypto from 'node:crypto'
import { and, desc, eq, like, or } from 'drizzle-orm'
import { getDb } from './index'
import { auditLogs, type AuditLogRow, type AuditStatus } from './schema'

export interface RecordAuditInput {
  actorOid: string
  actorUpn: string
  actorRole: string
  action: string
  target: string
  status: AuditStatus
  details?: Record<string, unknown>
  ipAddress?: string | null
}

export function recordAuditLog(input: RecordAuditInput): AuditLogRow {
  const db = getDb()
  const row: AuditLogRow = {
    id: crypto.randomUUID(),
    actorOid: input.actorOid,
    actorUpn: input.actorUpn,
    actorRole: input.actorRole,
    action: input.action,
    target: input.target,
    status: input.status,
    detailsJson: JSON.stringify(input.details ?? {}),
    ipAddress: input.ipAddress ?? null,
    createdAt: Date.now(),
  }

  db.insert(auditLogs).values(row).run()
  return row
}

export interface ListAuditLogsOptions {
  limit?: number
  action?: string
  status?: AuditStatus | 'all'
  search?: string
}

export function listAuditLogs(options: ListAuditLogsOptions = {}): AuditLogRow[] {
  const db = getDb()
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 500)
  const conditions = []

  if (options.action && options.action !== 'all') {
    conditions.push(eq(auditLogs.action, options.action))
  }
  if (options.status && options.status !== 'all') {
    conditions.push(eq(auditLogs.status, options.status))
  }
  if (options.search?.trim()) {
    const pattern = `%${options.search.trim()}%`
    conditions.push(
      or(
        like(auditLogs.actorUpn, pattern),
        like(auditLogs.target, pattern),
        like(auditLogs.action, pattern),
        like(auditLogs.detailsJson, pattern),
      ),
    )
  }

  const query = db
    .select()
    .from(auditLogs)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit)

  return query.all()
}
