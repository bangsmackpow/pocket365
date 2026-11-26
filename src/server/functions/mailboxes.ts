import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireCapability, requireRole, requireSession } from '~/server/auth/guards'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { jobs } from '~/server/db/schema'
import {
  getGraphClient,
  type GraphMailboxSettings,
} from '~/server/graph/client'
import {
  analyzeInboxRuleRisk,
  type InboxRuleRiskAnalysis,
} from '~/server/graph/insights-helpers'
import {
  enqueueJob,
  type MailboxBecSweepResult,
} from '~/server/graph/jobs'
import {
  classifyGraphError,
  type FriendlyGraphError,
} from '~/server/graph/signin-errors'
import { getClientIp } from '~/server/http/proxy'
import { enforceRateLimit } from '~/server/security/rate-limit'

const mailboxDetailSchema = z.object({
  userId: z.string().min(1),
})

export const getMailboxAuditFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => mailboxDetailSchema.parse(input))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()

    const [settingsOutcome, rulesOutcome] = await Promise.all([
      graph
        .getUserMailboxSettings(data.userId)
        .then((s) => ({
          settings: s as GraphMailboxSettings | null,
          error: null as FriendlyGraphError | null,
        }))
        .catch((err) => ({
          settings: null as GraphMailboxSettings | null,
          error: classifyGraphError(err, ['MailboxSettings.ReadWrite']) as FriendlyGraphError | null,
        })),
      graph
        .listUserInboxRules(data.userId)
        .then((rawRules) => ({
          rules: rawRules.map(analyzeInboxRuleRisk),
          error: null as FriendlyGraphError | null,
        }))
        .catch((err) => ({
          rules: [] as InboxRuleRiskAnalysis[],
          error: classifyGraphError(err, ['Mail.ReadWrite']) as FriendlyGraphError | null,
        })),
    ])

    return {
      settings: settingsOutcome.settings,
      settingsError: settingsOutcome.error,
      rules: rulesOutcome.rules,
      rulesError: rulesOutcome.error,
      highRiskRulesCount: rulesOutcome.rules.filter((r) => r.riskLevel === 'high')
        .length,
    }
  })

const updateAutoReplySchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  status: z.enum(['disabled', 'alwaysEnabled', 'scheduled']),
  externalAudience: z.enum(['none', 'contactsOnly', 'all']).default('all'),
  internalReplyMessage: z.string().max(4000).default(''),
  externalReplyMessage: z.string().max(4000).default(''),
  scheduledStartIso: z.string().optional(),
  scheduledEndIso: z.string().optional(),
})

export const updateMailboxAutoReplyFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => updateAutoReplySchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireCapability('helpdesk.actions', undefined, 'mailbox.update_autoreply')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      const payload = {
        status: data.status,
        externalAudience: data.externalAudience,
        internalReplyMessage: data.internalReplyMessage,
        externalReplyMessage: data.externalReplyMessage,
        ...(data.status === 'scheduled' &&
        data.scheduledStartIso &&
        data.scheduledEndIso
          ? {
              scheduledStartDateTime: {
                dateTime: data.scheduledStartIso,
                timeZone: 'UTC',
              },
              scheduledEndDateTime: {
                dateTime: data.scheduledEndIso,
                timeZone: 'UTC',
              },
            }
          : {}),
      }

      const updated = await graph.updateUserAutoReplies(data.userId, payload)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'mailbox.update_autoreply',
        target: data.userPrincipalName,
        status: 'success',
        details: {
          userId: data.userId,
          status: data.status,
          externalAudience: data.externalAudience,
        },
        ipAddress,
      })
      return { ok: true, settings: updated }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'mailbox.update_autoreply',
        target: data.userPrincipalName,
        status: 'failure',
        details: {
          userId: data.userId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

const deleteInboxRuleSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  ruleId: z.string().min(1),
  ruleDisplayName: z.string().min(1),
})

export const deleteInboxRuleFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => deleteInboxRuleSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'mailbox.delete_rule')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.deleteUserInboxRule(data.userId, data.ruleId)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'mailbox.delete_rule',
        target: `${data.userPrincipalName} :: ${data.ruleDisplayName}`,
        status: 'success',
        details: { userId: data.userId, ruleId: data.ruleId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'mailbox.delete_rule',
        target: `${data.userPrincipalName} :: ${data.ruleDisplayName}`,
        status: 'failure',
        details: {
          userId: data.userId,
          ruleId: data.ruleId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

const becSweepSchema = z.object({
  onlyLicensed: z.boolean().default(true),
  maxUsers: z.number().int().min(10).max(250).default(100),
})

export const enqueueMailboxBecSweepFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => becSweepSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    const session = requireCapability('audit.sweep', undefined, 'mailbox.bec_sweep')
    enforceRateLimit('heavy', session.oid)
    const job = enqueueJob({
      type: 'mailbox.bec_sweep',
      payload: {
        onlyLicensed: data.onlyLicensed,
        maxUsers: data.maxUsers,
      },
      actor: { oid: session.oid, upn: session.upn, role: session.role },
      ipAddress: getClientIp(getRequest()),
    })
    return { job }
  })

export const getLatestBecSweepFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    requireSession()
    const db = getDb()
    const latest = db
      .select()
      .from(jobs)
      .where(eq(jobs.type, 'mailbox.bec_sweep'))
      .orderBy(desc(jobs.createdAt))
      .limit(1)
      .get()

    if (!latest) {
      return { job: null, result: null as MailboxBecSweepResult | null }
    }

    let result: MailboxBecSweepResult | null = null
    if (latest.resultJson) {
      try {
        result = JSON.parse(latest.resultJson) as MailboxBecSweepResult
      } catch {
        result = null
      }
    }

    return {
      job: {
        id: latest.id,
        status: latest.status,
        actorUpn: latest.actorUpn,
        createdAt: latest.createdAt,
        completedAt: latest.completedAt,
        error: latest.error,
      },
      result,
    }
  },
)
