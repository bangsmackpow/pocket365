import crypto from 'node:crypto'
import { asc, desc, eq } from 'drizzle-orm'
import { getCloudflareEnv, scheduleBackgroundTask } from '~/server/cf/env'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { jobs, type JobRow, type JobStatus, type UserRole } from '~/server/db/schema'
import { getRuntimeSettings } from '~/server/db/settings'
import { DEFAULT_ORG_ID } from '~/server/orgs/service'
import { getGraphClient, type MicrosoftGraphClient } from './client'
import {
  analyzeInboxRuleRisk,
  type InboxRuleRiskAnalysis,
} from './insights-helpers'

export type JobType =
  | 'user.bulk_toggle_enabled'
  | 'user.bulk_assign_license'
  | 'group.bulk_add_members'
  | 'group.bulk_remove_members'
  | 'user.offboard'
  | 'mailbox.bec_sweep'

export interface MailboxBecSweepPayload {
  onlyLicensed: boolean
  maxUsers: number
}

export interface MailboxBecFinding {
  userId: string
  displayName: string
  userPrincipalName: string
  rule: InboxRuleRiskAnalysis
}

export interface MailboxBecSweepResult {
  total: number
  succeeded: number
  failed: number
  scannedUsers: number
  totalRulesInspected: number
  highRiskCount: number
  mediumRiskCount: number
  findings: MailboxBecFinding[]
  items: BulkItemOutcome[]
}

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
  | MailboxBecSweepPayload

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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function dispatchJobExecution(jobId: string): Promise<void> {
  const queue = getCloudflareEnv().POCKET365_QUEUE
  if (queue) {
    await queue.send({ kind: 'job', jobId })
    return
  }
  // Cloudflare Free plan / local dev fallback: run inside ctx.waitUntil()
  scheduleBackgroundTask(processJobById(jobId))
}

export async function enqueueJob(params: {
  organizationId?: string
  type: JobType
  payload: JobPayload
  actor: JobActor
  ipAddress?: string | null
  maxAttempts?: number
  autoStartWorker?: boolean
}): Promise<JobRow> {
  const db = getDb()
  const now = Date.now()
  const organizationId = params.organizationId?.trim() || DEFAULT_ORG_ID
  const row: JobRow = {
    id: crypto.randomUUID(),
    organizationId,
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

  await db.insert(jobs).values(row).run()

  await recordAuditLog({
    organizationId,
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
    await dispatchJobExecution(row.id)
  }

  return row
}

export async function listJobs(options: {
  organizationId?: string
  limit?: number
  status?: JobStatus | 'all'
} = {}): Promise<JobRow[]> {
  const db = getDb()
  const limit = Math.min(Math.max(options.limit ?? 50, 1), 200)
  const orgId = options.organizationId?.trim() || DEFAULT_ORG_ID
  const rows = await db
    .select()
    .from(jobs)
    .where(eq(jobs.organizationId, orgId))
    .orderBy(desc(jobs.createdAt))
    .limit(limit)
    .all()

  if (options.status && options.status !== 'all') {
    return rows.filter((r) => r.status === options.status)
  }
  return rows
}

export async function getJobById(jobId: string): Promise<JobRow | null> {
  const db = getDb()
  return (
    (await db.select().from(jobs).where(eq(jobs.id, jobId)).get()) ?? null
  )
}

export async function retryFailedJob(
  jobId: string,
  actor: JobActor,
  ipAddress?: string | null,
): Promise<JobRow> {
  const db = getDb()
  const existing = await getJobById(jobId)
  if (!existing) {
    throw new Error('Job not found.')
  }
  if (existing.status !== 'failed') {
    throw new Error('Only failed jobs can be retried.')
  }

  const now = Date.now()
  await db
    .update(jobs)
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

  await recordAuditLog({
    actorOid: actor.oid,
    actorUpn: actor.upn,
    actorRole: actor.role,
    action: 'job.retry',
    target: jobId,
    status: 'queued',
    details: { type: existing.type },
    ipAddress: ipAddress ?? null,
  })

  await dispatchJobExecution(jobId)

  const refreshed = await getJobById(jobId)
  return refreshed!
}

async function executeJob(
  job: JobRow,
  graphClient: MicrosoftGraphClient,
  delayMs: number,
): Promise<BulkJobResult | MailboxBecSweepResult> {
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
    case 'mailbox.bec_sweep': {
      const payload = JSON.parse(job.payloadJson) as MailboxBecSweepPayload
      const page = await graphClient.listUsers({
        top: Math.min(Math.max(payload.maxUsers || 100, 1), 250),
      })
      const targets = page.items.filter((u) => {
        if (u.accountEnabled === false) return false
        if (payload.onlyLicensed && u.assignedLicenses.length === 0) {
          return false
        }
        return true
      })

      const findings: MailboxBecFinding[] = []
      let totalRulesInspected = 0

      for (const u of targets) {
        try {
          const rules = await graphClient.listUserInboxRules(u.id)
          totalRulesInspected += rules.length
          for (const rawRule of rules) {
            const analyzed = analyzeInboxRuleRisk(rawRule)
            if (analyzed.riskLevel === 'high' || analyzed.riskLevel === 'medium') {
              findings.push({
                userId: u.id,
                displayName: u.displayName,
                userPrincipalName: u.userPrincipalName,
                rule: analyzed,
              })
            }
          }
          items.push({ targetId: u.userPrincipalName, ok: true })
        } catch (err) {
          // Users without Exchange mailbox return 404/MailboxNotEnabledForRESTAPI; record cleanly
          items.push({
            targetId: u.userPrincipalName,
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          })
        }
        if (delayMs > 0) {
          await sleep(delayMs)
        }
      }

      const succeeded = items.filter((i) => i.ok).length
      const failed = items.length - succeeded
      return {
        total: items.length,
        succeeded,
        failed,
        scannedUsers: targets.length,
        totalRulesInspected,
        highRiskCount: findings.filter((f) => f.rule.riskLevel === 'high').length,
        mediumRiskCount: findings.filter((f) => f.rule.riskLevel === 'medium')
          .length,
        findings,
        items,
      }
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

async function runClaimedJob(
  targetJob: JobRow,
  graphClient: MicrosoftGraphClient,
  delayOverrideMs?: number,
): Promise<JobRow | null> {
  const db = getDb()
  const now = Date.now()
  const nextAttempt = targetJob.attempts + 1

  await db
    .update(jobs)
    .set({
      status: 'running',
      attempts: nextAttempt,
      startedAt: targetJob.startedAt ?? now,
      updatedAt: now,
    })
    .where(eq(jobs.id, targetJob.id))
    .run()

  try {
    const settings = await getRuntimeSettings()
    const delayMs = delayOverrideMs ?? settings.bulkJobDelayMs
    const result = await executeJob(targetJob, graphClient, delayMs)
    const finishedAt = Date.now()
    const allFailed = result.total > 0 && result.succeeded === 0

    await db
      .update(jobs)
      .set({
        status: allFailed ? 'failed' : 'completed',
        resultJson: JSON.stringify(result),
        error: allFailed
          ? `All ${result.failed} target operations failed.`
          : null,
        completedAt: finishedAt,
        updatedAt: finishedAt,
      })
      .where(eq(jobs.id, targetJob.id))
      .run()

    await recordAuditLog({
      actorOid: targetJob.actorOid,
      actorUpn: targetJob.actorUpn,
      actorRole: targetJob.actorRole,
      action: `job.complete:${targetJob.type}`,
      target: targetJob.id,
      status: allFailed ? 'failure' : 'success',
      details: {
        total: result.total,
        succeeded: result.succeeded,
        failed: result.failed,
      },
    })
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    const canRetry = nextAttempt < targetJob.maxAttempts
    const finishedAt = Date.now()

    await db
      .update(jobs)
      .set({
        status: canRetry ? 'queued' : 'failed',
        error: message,
        completedAt: canRetry ? null : finishedAt,
        updatedAt: finishedAt,
      })
      .where(eq(jobs.id, targetJob.id))
      .run()

    if (!canRetry) {
      await recordAuditLog({
        actorOid: targetJob.actorOid,
        actorUpn: targetJob.actorUpn,
        actorRole: targetJob.actorRole,
        action: `job.failed:${targetJob.type}`,
        target: targetJob.id,
        status: 'failure',
        details: { error: message, attempts: nextAttempt },
      })
    }
  }

  return getJobById(targetJob.id)
}

export async function processJobById(
  jobId: string,
  explicitGraphClient?: MicrosoftGraphClient,
  delayOverrideMs?: number,
): Promise<JobRow | null> {
  const job = await getJobById(jobId)
  if (!job || job.status !== 'queued') return job
  const graphClient = explicitGraphClient ?? (await getGraphClient())
  return runClaimedJob(job, graphClient, delayOverrideMs)
}

export async function processNextQueuedJob(
  explicitGraphClient?: MicrosoftGraphClient,
  delayOverrideMs?: number,
): Promise<JobRow | null> {
  const db = getDb()
  const nextJob = await db
    .select()
    .from(jobs)
    .where(eq(jobs.status, 'queued'))
    .orderBy(asc(jobs.createdAt))
    .limit(1)
    .get()

  if (!nextJob) return null
  const graphClient = explicitGraphClient ?? (await getGraphClient())
  return runClaimedJob(nextJob, graphClient, delayOverrideMs)
}

/**
 * Drains up to `maxJobs` pending queued jobs — invoked by Cloudflare Cron Triggers.
 */
export async function drainQueuedJobs(maxJobs = 10): Promise<number> {
  let processedCount = 0
  for (let i = 0; i < maxJobs; i++) {
    const job = await processNextQueuedJob()
    if (!job) break
    processedCount++
  }
  return processedCount
}
