import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import {
  ensureAlertSchedulerStarted,
  recordAndDispatchAlert,
  runAutomatedAlertChecks,
} from '~/server/alerts/engine'
import { requireRole, requireSession } from '~/server/auth/guards'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { alertEvents, alertWebhooks } from '~/server/db/schema'
import { getClientIp } from '~/server/http/proxy'

function maskWebhookUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host}/••••${url.slice(-6)}`
  } catch {
    return '••••••'
  }
}

export const getAlertsDashboardFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    const session = requireSession()
    ensureAlertSchedulerStarted()
    const db = getDb()

    const rawWebhooks = db
      .select()
      .from(alertWebhooks)
      .orderBy(desc(alertWebhooks.createdAt))
      .all()

    const events = db
      .select()
      .from(alertEvents)
      .orderBy(desc(alertEvents.createdAt))
      .limit(100)
      .all()

    return {
      webhooks: rawWebhooks.map((w) => ({
        id: w.id,
        name: w.name,
        provider: w.provider,
        maskedUrl: maskWebhookUrl(w.url),
        enabled: w.enabled === 1,
        createdBy: w.createdBy,
        createdAt: w.createdAt,
        isAdminView: session.role === 'admin',
      })),
      events,
    }
  },
)

const createWebhookSchema = z.object({
  name: z.string().min(2).max(80),
  provider: z.enum(['teams', 'slack', 'discord', 'generic']),
  url: z
    .string()
    .url()
    .refine((u) => u.startsWith('https://') || u.startsWith('http://'), {
      message: 'Webhook URL must start with https:// or http://',
    }),
})

export const addAlertWebhookFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => createWebhookSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'alerts.add_webhook')
    const db = getDb()
    const now = Date.now()
    const id = crypto.randomUUID()

    db.insert(alertWebhooks)
      .values({
        id,
        name: data.name.trim(),
        provider: data.provider,
        url: data.url.trim(),
        enabled: 1,
        createdBy: session.upn,
        createdAt: now,
        updatedAt: now,
      })
      .run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'alerts.add_webhook',
      target: data.name.trim(),
      status: 'success',
      details: { id, provider: data.provider },
      ipAddress: getClientIp(getRequest()),
    })

    ensureAlertSchedulerStarted()
    return { ok: true, id }
  })

const toggleWebhookSchema = z.object({
  id: z.string().uuid(),
  enabled: z.boolean(),
})

export const toggleAlertWebhookFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => toggleWebhookSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'alerts.toggle_webhook')
    const db = getDb()
    db.update(alertWebhooks)
      .set({ enabled: data.enabled ? 1 : 0, updatedAt: Date.now() })
      .where(eq(alertWebhooks.id, data.id))
      .run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'alerts.toggle_webhook',
      target: data.id,
      status: 'success',
      details: { enabled: data.enabled },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

const deleteWebhookSchema = z.object({
  id: z.string().uuid(),
})

export const deleteAlertWebhookFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => deleteWebhookSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'alerts.delete_webhook')
    const db = getDb()
    db.delete(alertWebhooks).where(eq(alertWebhooks.id, data.id)).run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'alerts.delete_webhook',
      target: data.id,
      status: 'success',
      details: {},
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

export const sendTestAlertFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const session = requireRole('admin', undefined, 'alerts.test_webhook')
    const res = await recordAndDispatchAlert(
      {
        ruleKey: 'manual_test',
        dedupeKey: `test:${Date.now()}`,
        severity: 'info',
        title: 'Pocket365 Test Notification',
        message: `Webhook delivery test triggered by ${session.upn}. Automated drift & security alerts are connected.`,
        details: { triggeredBy: session.upn },
      },
      { skipDedupe: true },
    )

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'alerts.test_webhook',
      target: 'all_enabled_webhooks',
      status: res.event?.deliveryStatus === 'failed' ? 'failure' : 'success',
      details: { deliveryStatus: res.event?.deliveryStatus ?? 'none' },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, deliveryStatus: res.event?.deliveryStatus ?? 'none' }
  },
)

export const runAlertChecksNowFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const session = requireRole('admin', undefined, 'alerts.run_checks')
    const summary = await runAutomatedAlertChecks()
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'alerts.run_checks',
      target: 'alert_engine',
      status: 'success',
      details: { ...summary },
      ipAddress: getClientIp(getRequest()),
    })
    return summary
  },
)
