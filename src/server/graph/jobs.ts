import crypto from 'node:crypto'
import { asc, desc, eq } from 'drizzle-orm'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { jobs, type JobRow, type JobStatus, type UserRole } from '~/server/db/schema'
import { getRuntimeSettings } from '~/server/db/settings'
import { getGraphClient, type MicrosoftGraphClient } from './client'

export type JobType =
  | 'user.bulk_toggle_enabled'
  | 'user.bulk_assign_license'
  | 'group.bulk_add_members'
  | 'group.bulk_remove_members'
  | 'user.offboard'

export interface BulkToggleUsersPayload {
  userIds: string[]
  accountEnabled: boolean
}

export interface BulkAssignLicensePayload {
  userIds: string[]
  addSkuIds: string[]
  removeSkuIds: string[]
}

export interface BulkGroupMembersPayload {
  groupId: string
  userIds: string[]
}

export interface UserOffboardPayload {
  userId: string
  userPrincipalName: string
  mode: 'emergency_lockout' | 'full_offboard'
  disableAccount: boolean
  revokeSessions: boolean
  scramblePassword: boolean
  removeAllLicenses: boolean
  removeFromGroups: boolean
  clearManager: boolean
}

export type JobPayload =
  | BulkToggleUsersPayload
  | BulkAssignLicensePayload
  | BulkGroupMembersPayload
  | UserOffboardPayload

export function generateStrongPassword(length = 24): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  const lower = 'abcdefghijkmnopqrstuvwxyz'
  const digits = '23456789'
  const symbols = '!@#$%^&*-_=+'
  const all = upper + lower + digits + symbols

  const pick = (charset: string) => {
    const idx = crypto.randomInt(0, charset.length)
    return charset[idx]!
  }

  const chars = [pick(upper), pick(lower), pick(digits), pick(symbols)]
  while (chars.length < Math.max(length, 16)) {
    chars.push(pick(all))
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1)
    const tmp = chars[i]!
    chars[i] = chars[j]!
    chars[j] = tmp
  }

  return chars.join('')
}

export interface JobActor {
  oid: string
  upn: string
  role: UserRole
}

export interface BulkItemOutcome {
  targetId: string
  ok: boolean
  error?: string
}

export interface BulkJobResult {
  total: number
  succeeded: number
  failed: number
  items: BulkItemOutcome[]
}

const POLL_INTERVAL_MS = 5_000

let workerStarted = false
let workerRunning = false
let pollTimer: NodeJS.Timeout | null = null

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function enqueueJob(params: {
  type: JobType
  payload: JobPayload
  actor: JobActor
  ipAddress?: string | null
  maxAttempts?: number
  autoStartWorker?: boolean
}): JobRow {
  const db = getDb()
  const now = Date.now()
  const row: JobRow = {
    id: crypto.randomUUID(),
    type: params.type,
    status: 'queued',
    payloadJson: JSON.stringify(params.payload),
    resultJson: null,
    error: null,
    actorOid: params.actor.oid,
    actorUpn: params.actor.upn,
    actorRole: params.actor.role,
    attempts: 0,
    maxAttempts: params.maxAttempts ?? 3,
    createdAt: now,
    startedAt: null,
    completedAt: null,
    updatedAt: now,
  }

  db.insert(jobs).values(row).run()

  recordAuditLog({
    actorOid: params.actor.oid,
    actorUpn: params.actor.upn,
    actorRole: params.actor.role,
    action: `job.enqueue:${params.type}`,
    target: row.id,
    status: 'queued',
    details: { jobId: row.id, payload: params.payload },
    ipAddress: params.ipAddress ?? null,
  })

  if (params.autoStartWorker !== false) {
    ensureJobWorkerStarted()
    triggerJobProcessing()
  }

  return row
}

export function listJobs(options: {
  limit?: number
  status?: JobStatus | 'all'
} = {}): JobRow[] {
  const db = getDb()
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200)
  return db
    .select()
    .from(jobs)
    .where(
      options.status && options.status !== 'all'
        ? eq(jobs.status, options.status)
        : undefined,
    )
    .orderBy(desc(jobs.createdAt))
    .limit(limit)
    .all()
}

export function getJobById(jobId: string): JobRow | null {
  const db = getDb()
  return db.select().from(jobs).where(eq(jobs.id, jobId)).get() ?? null
}

export function retryFailedJob(
  jobId: string,
  actor: JobActor,
  ipAddress?: string | null,
): JobRow {
  const db = getDb()
  const existing = getJobById(jobId)
  if (!existing) {
    throw new Error('Job not found.')
  }
  if (existing.status !== 'failed') {
    throw new Error('Only failed jobs can be retried.')
  }

  const now = Date.now()
  db.update(jobs)
    .set({
      status: 'queued',
      error: null,
      attempts: 0,
      startedAt: null,
      completedAt: null,
      updatedAt: now,
    })
    .where(eq(jobs.id, jobId))
    .run()

  recordAuditLog({
    actorOid: actor.oid,
    actorUpn: actor.upn,
    actorRole: actor.role,
    action: 'job.retry',
    target: jobId,
    status: 'queued',
    details: { type: existing.type },
    ipAddress: ipAddress ?? null,
  })

  ensureJobWorkerStarted()
  triggerJobProcessing()

  return getJobById(jobId)!
}

async function executeJob(
  job: JobRow,
  graphClient: MicrosoftGraphClient,
  delayMs: number,
): Promise<BulkJobResult> {
  const items: BulkItemOutcome[] = []

  const runItem = async (targetId: string, fn: () => Promise<void>) => {
    try {
      await fn()
      items.push({ targetId, ok: true })
    } catch (err) {
      items.push({
        targetId,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      })
    }
    if (delayMs > 0) {
      await sleep(delayMs)
    }
  }

  switch (job.type as JobType) {
    case 'user.bulk_toggle_enabled': {
      const payload = JSON.parse(job.payloadJson) as BulkToggleUsersPayload
      for (const userId of payload.userIds) {
        await runItem(userId, () =>
          graphClient.setUserAccountEnabled(userId, payload.accountEnabled),
        )
      }
      break
    }
    case 'user.bulk_assign_license': {
      const payload = JSON.parse(job.payloadJson) as BulkAssignLicensePayload
      for (const userId of payload.userIds) {
        await runItem(userId, async () => {
          await graphClient.assignUserLicenses(
            userId,
            payload.addSkuIds,
            payload.removeSkuIds,
          )
        })
      }
      break
    }
    case 'group.bulk_add_members': {
      const payload = JSON.parse(job.payloadJson) as BulkGroupMembersPayload
      for (const userId of payload.userIds) {
        await runItem(userId, () =>
          graphClient.addGroupMember(payload.groupId, userId),
        )
      }
      break
    }
    case 'group.bulk_remove_members': {
      const payload = JSON.parse(job.payloadJson) as BulkGroupMembersPayload
      for (const userId of payload.userIds) {
        await runItem(userId, () =>
          graphClient.removeGroupMember(payload.groupId, userId),
        )
      }
      break
    }
    case 'user.offboard': {
      const payload = JSON.parse(job.payloadJson) as UserOffboardPayload

      if (payload.disableAccount) {
        await runItem('disable_account', () =>
          graphClient.setUserAccountEnabled(payload.userId, false),
        )
      }

      if (payload.revokeSessions) {
        await runItem('revoke_sessions', async () => {
          await graphClient.revokeUserSignInSessions(payload.userId)
        })
      }

      if (payload.scramblePassword) {
        await runItem('scramble_password', () =>
          graphClient.resetUserPassword(
            payload.userId,
            generateStrongPassword(24),
            true,
          ),
        )
      }

      if (payload.removeAllLicenses) {
        await runItem('remove_all_licenses', async () => {
          const user = await graphClient.getUser(payload.userId)
          const skuIds = user.assignedLicenses.map((l) => l.skuId)
          if (skuIds.length > 0) {
            await graphClient.assignUserLicenses(payload.userId, [], skuIds)
          }
        })
      }

      if (payload.removeFromGroups) {
        let memberships: Awaited<
          ReturnType<MicrosoftGraphClient['listUserDirectMemberships']>
        > = []
        try {
          memberships = await graphClient.listUserDirectMemberships(
            payload.userId,
          )
        } catch (err) {
          items.push({
            targetId: 'list_group_memberships',
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          })
        }

        const assignableGroups = memberships.filter(
          (m) =>
            m['@odata.type'] === '#microsoft.graph.group' &&
            !(m.groupTypes ?? []).includes('DynamicMembership'),
        )

        if (assignableGroups.length === 0) {
          items.push({ targetId: 'remove_groups:none_assigned', ok: true })
        } else {
          for (const grp of assignableGroups) {
            await runItem(
              `remove_group:${grp.displayName || grp.id}`,
              () => graphClient.removeGroupMember(grp.id, payload.userId),
            )
          }
        }
      }

      if (payload.clearManager) {
        await runItem('clear_manager', async () => {
          try {
            await graphClient.clearUserManager(payload.userId)
          } catch (err) {
            // 404 means no manager was assigned — treat as clean no-op
            if (err instanceof Error && /404|not found|Resource 'manager' does not exist/i.test(err.message)) {
              return
            }
            throw err
          }
        })
      }

      break
    }
    default:
      throw new Error(`Unsupported job type: ${job.type}`)
  }

  const succeeded = items.filter((item) => item.ok).length
  const failed = items.length - succeeded
  return {
    total: items.length,
    succeeded,
    failed,
    items,
  }
}

export async function processNextQueuedJob(
  graphClient: MicrosoftGraphClient = getGraphClient(),
  delayOverrideMs?: number,
): Promise<JobRow | null> {
  const db = getDb()
  const nextJob = db
    .select()
    .from(jobs)
    .where(eq(jobs.status, 'queued'))
    .orderBy(asc(jobs.createdAt))
    .limit(1)
    .get()

  if (!nextJob) return null

  const now = Date.now()
  const nextAttempt = nextJob.attempts + 1

  db.update(jobs)
    .set({
      status: 'running',
      attempts: nextAttempt,
      startedAt: nextJob.startedAt ?? now,
      updatedAt: now,
    })
    .where(eq(jobs.id, nextJob.id))
    .run()

  try {
    const settings = getRuntimeSettings()
    const delayMs = delayOverrideMs ?? settings.bulkJobDelayMs
    const result = await executeJob(nextJob, graphClient, delayMs)
    const finishedAt = Date.now()
    const allFailed = result.total > 0 && result.succeeded === 0

    db.update(jobs)
      .set({
        status: allFailed ? 'failed' : 'completed',
        resultJson: JSON.stringify(result),
        error: allFailed
          ? `All ${result.failed} target operations failed.`
          : null,
        completedAt: finishedAt,
        updatedAt: finishedAt,
      })
      .where(eq(jobs.id, nextJob.id))
      .run()

    recordAuditLog({
      actorOid: nextJob.actorOid,
      actorUpn: nextJob.actorUpn,
      actorRole: nextJob.actorRole,
      action: `job.complete:${nextJob.type}`,
      target: nextJob.id,
      status: allFailed ? 'failure' : 'success',
      details: {
        total: result.total,
        succeeded: result.succeeded,
        failed: result.failed,
      },
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    const canRetry = nextAttempt < nextJob.maxAttempts
    const finishedAt = Date.now()

    db.update(jobs)
      .set({
        status: canRetry ? 'queued' : 'failed',
        error: message,
        completedAt: canRetry ? null : finishedAt,
        updatedAt: finishedAt,
      })
      .where(eq(jobs.id, nextJob.id))
      .run()

    if (!canRetry) {
      recordAuditLog({
        actorOid: nextJob.actorOid,
        actorUpn: nextJob.actorUpn,
        actorRole: nextJob.actorRole,
        action: `job.failed:${nextJob.type}`,
        target: nextJob.id,
        status: 'failure',
        details: { error: message, attempts: nextAttempt },
      })
    }
  }

  return getJobById(nextJob.id)
}

export function triggerJobProcessing(): void {
  if (workerRunning) return
  workerRunning = true
  setImmediate(async () => {
    try {
      while (true) {
        const processed = await processNextQueuedJob()
        if (!processed) break
      }
    } catch {
      // Errors are persisted per-job; keep worker alive
    } finally {
      workerRunning = false
    }
  })
}

export function ensureJobWorkerStarted(): void {
  if (workerStarted) return
  workerStarted = true

  // Recover any jobs left in 'running' state after a container restart
  const db = getDb()
  db.update(jobs)
    .set({ status: 'queued', updatedAt: Date.now() })
    .where(eq(jobs.status, 'running'))
    .run()

  pollTimer = setInterval(() => {
    triggerJobProcessing()
  }, POLL_INTERVAL_MS)
  pollTimer.unref?.()
}

export function stopJobWorker(): void {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  workerStarted = false
  workerRunning = false
}
