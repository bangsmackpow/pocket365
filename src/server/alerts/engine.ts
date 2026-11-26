import crypto from 'node:crypto'
import { and, desc, eq, gte } from 'drizzle-orm'
import { getEffectiveConfigReadiness } from '~/server/setup/service'
import { getDb } from '~/server/db'
import {
  alertEvents,
  alertWebhooks,
  cisSnapshots,
  policySnapshots,
  type AlertEventRow,
  type AlertWebhookRow,
  type WebhookProvider,
} from '~/server/db/schema'
import type { CisCheckResult } from '~/server/graph/cis-benchmarks'
import { getGraphClient, type MicrosoftGraphClient } from '~/server/graph/client'
import { analyzeAppCredentials } from '~/server/graph/insights-helpers'
import { collectCisScan } from '~/server/graph/cis-scanner'
import { DEFAULT_ORG_ID } from '~/server/orgs/service'
import { decryptSecret } from '~/server/security/crypto'
import { assertSafeWebhookUrl } from '~/server/security/ssrf'

export interface OutgoingAlert {
  ruleKey: string
  dedupeKey: string
  severity: 'critical' | 'high' | 'medium' | 'info'
  title: string
  message: string
  details?: Record<string, unknown>
}

const DEDUPE_WINDOW_MS = 24 * 60 * 60 * 1000

export function formatWebhookPayload(
  provider: WebhookProvider,
  alert: OutgoingAlert,
): Record<string, unknown> {
  const colorHex =
    alert.severity === 'critical'
      ? 'DC2626'
      : alert.severity === 'high'
        ? 'EA580C'
        : alert.severity === 'medium'
          ? 'D97706'
          : '4F46E5'

  switch (provider) {
    case 'teams':
      return {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        themeColor: colorHex,
        summary: `[Pocket365] ${alert.title}`,
        title: `[Pocket365 ${alert.severity.toUpperCase()}] ${alert.title}`,
        text: alert.message,
        sections: alert.details
          ? [
              {
                facts: Object.entries(alert.details).map(([name, value]) => ({
                  name,
                  value:
                    typeof value === 'string' ? value : JSON.stringify(value),
                })),
              },
            ]
          : [],
      }
    case 'slack':
      return {
        text: `*[Pocket365 ${alert.severity.toUpperCase()}] ${alert.title}*\n${alert.message}`,
      }
    case 'discord':
      return {
        embeds: [
          {
            title: `[Pocket365 ${alert.severity.toUpperCase()}] ${alert.title}`,
            description: alert.message,
            color: Number.parseInt(colorHex, 16),
            timestamp: new Date().toISOString(),
          },
        ],
      }
    case 'generic':
    default:
      return {
        source: 'pocket365',
        timestamp: new Date().toISOString(),
        ...alert,
      }
  }
}

export async function deliverAlertToWebhooks(
  alert: OutgoingAlert,
  webhooks: AlertWebhookRow[],
  fetchImpl: typeof fetch = fetch,
): Promise<{ delivered: number; failed: number; errors: string[] }> {
  const enabledHooks = webhooks.filter((w) => w.enabled === 1)
  if (enabledHooks.length === 0) {
    return { delivered: 0, failed: 0, errors: [] }
  }

  let delivered = 0
  let failed = 0
  const errors: string[] = []

  const rawFetch = fetchImpl ?? globalThis.fetch
  for (const hook of enabledHooks) {
    try {
      const targetUrl = decryptSecret(hook.url)
      await assertSafeWebhookUrl(targetUrl)
      const res = await rawFetch.call(globalThis, targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formatWebhookPayload(hook.provider, alert)),
      })
      if (res.ok) {
        delivered++
      } else {
        failed++
        errors.push(`${hook.name}: HTTP ${res.status}`)
      }
    } catch (err) {
      failed++
      errors.push(
        `${hook.name}: ${err instanceof Error ? err.message : String(err)}`,
      )
    }
  }

  return { delivered, failed, errors }
}

export async function recordAndDispatchAlert(
  alert: OutgoingAlert,
  options: {
    organizationId?: string
    skipDedupe?: boolean
    fetchImpl?: typeof fetch
  } = {},
): Promise<{ skipped: boolean; event?: AlertEventRow }> {
  const db = getDb()
  const now = Date.now()
  const organizationId = options.organizationId?.trim() || DEFAULT_ORG_ID

  if (!options.skipDedupe) {
    const recent = await db
      .select()
      .from(alertEvents)
      .where(
        and(
          eq(alertEvents.organizationId, organizationId),
          eq(alertEvents.dedupeKey, alert.dedupeKey),
          gte(alertEvents.createdAt, now - DEDUPE_WINDOW_MS),
        ),
      )
      .limit(1)
      .get()
    if (recent) {
      return { skipped: true }
    }
  }

  const webhooks = await db
    .select()
    .from(alertWebhooks)
    .where(eq(alertWebhooks.organizationId, organizationId))
    .all()
  const result = await deliverAlertToWebhooks(
    alert,
    webhooks,
    options.fetchImpl ?? fetch,
  )

  const deliveryStatus =
    webhooks.filter((w) => w.enabled === 1).length === 0
      ? 'recorded_only'
      : result.failed === 0
        ? 'delivered'
        : result.delivered > 0
          ? 'partial'
          : 'failed'

  const event: AlertEventRow = {
    id: crypto.randomUUID(),
    organizationId,
    ruleKey: alert.ruleKey,
    dedupeKey: alert.dedupeKey,
    severity: alert.severity,
    title: alert.title,
    message: alert.message,
    detailsJson: JSON.stringify({
      ...(alert.details ?? {}),
      delivery: result,
    }),
    deliveryStatus,
    createdAt: now,
  }

  await db.insert(alertEvents).values(event).run()
  return { skipped: false, event }
}

export interface AlertRunSummary {
  checkedAt: string
  alertsTriggered: number
  alertsSkippedDedupe: number
  rulesEvaluated: string[]
}

export async function runAutomatedAlertChecks(
  explicitGraph?: MicrosoftGraphClient,
  fetchImpl: typeof fetch = fetch,
): Promise<AlertRunSummary> {
  const graph = explicitGraph ?? (await getGraphClient())
  const db = getDb()
  const alertsToSend: OutgoingAlert[] = []
  const rulesEvaluated: string[] = []

  // 1. Privileged Role Membership Drift Check (Netwrix #1 alert)
  try {
    const roles = await graph.listDirectoryRolesWithMembers()
    rulesEvaluated.push('privileged_role_change')
    const currentSnapshot: Record<string, string[]> = {}
    for (const r of roles) {
      currentSnapshot[r.displayName] = (r.members ?? [])
        .map((m) => m.userPrincipalName || m.displayName || m.id)
        .sort()
    }

    const prevBaseline = await db
      .select()
      .from(policySnapshots)
      .where(eq(policySnapshots.snapshotType, 'directory_roles'))
      .orderBy(desc(policySnapshots.createdAt))
      .limit(1)
      .get()

    if (prevBaseline) {
      const prevMap = JSON.parse(prevBaseline.payloadJson) as Record<
        string,
        string[]
      >
      for (const [roleName, members] of Object.entries(currentSnapshot)) {
        const prevSet = new Set(prevMap[roleName] ?? [])
        const added = members.filter((m) => !prevSet.has(m))
        if (added.length > 0) {
          const isGa = roleName.toLowerCase() === 'global administrator'
          alertsToSend.push({
            ruleKey: 'privileged_role_change',
            dedupeKey: `role_add:${roleName}:${added.join(',')}`,
            severity: isGa ? 'critical' : 'high',
            title: `New ${roleName} Assignment Detected`,
            message: `${added.join(', ')} was added to Entra directory role "${roleName}".`,
            details: { roleName, addedMembers: added },
          })
        }
      }
    }

    // Persist refreshed role baseline in D1
    await db
      .insert(policySnapshots)
      .values({
        id: crypto.randomUUID(),
        snapshotType: 'directory_roles',
        label: 'Auto Role Monitor Baseline',
        actorUpn: 'system:alert-engine',
        policyCount: roles.length,
        payloadJson: JSON.stringify(currentSnapshot),
        createdAt: Date.now(),
      })
      .run()
  } catch {
    // Skip if role permission isn't granted
  }

  // 2. Expiring App Secrets / Certificates (<= 30 days)
  try {
    const apps = await graph.listApplications(150)
    rulesEvaluated.push('expiring_app_credentials')
    const findings = analyzeAppCredentials(apps).filter(
      (c) => c.state === 'expired' || c.state === 'critical',
    )
    for (const f of findings.slice(0, 10)) {
      alertsToSend.push({
        ruleKey: 'expiring_app_credentials',
        dedupeKey: `app_cred:${f.appId}:${f.keyId}:${f.state}`,
        severity: f.state === 'expired' ? 'critical' : 'high',
        title: `App ${f.credentialType} ${f.state === 'expired' ? 'Expired' : 'Expiring Soon'}: ${f.appDisplayName}`,
        message: `${f.appDisplayName} (${f.credentialName}) ${
          f.daysRemaining !== null && f.daysRemaining < 0
            ? `expired ${Math.abs(f.daysRemaining)} day(s) ago`
            : `expires in ${f.daysRemaining} day(s)`
        }.`,
        details: { appId: f.appId, credential: f.credentialName },
      })
    }
  } catch {
    // Skip if Application.Read.All isn't granted
  }

  // 3. CIS Benchmark Regression vs Latest Snapshot
  try {
    const latestCis = await db
      .select()
      .from(cisSnapshots)
      .orderBy(desc(cisSnapshots.createdAt))
      .limit(1)
      .get()
    if (latestCis) {
      rulesEvaluated.push('cis_regression')
      const prevChecks = JSON.parse(latestCis.checksJson) as CisCheckResult[]
      const prevPassSet = new Set(
        prevChecks.filter((c) => c.status === 'pass').map((c) => c.id),
      )
      const currentScan = await collectCisScan()
      const regressions = currentScan.checks.filter(
        (c) => prevPassSet.has(c.id) && c.status === 'fail',
      )
      for (const reg of regressions) {
        alertsToSend.push({
          ruleKey: 'cis_regression',
          dedupeKey: `cis_regress:${reg.id}`,
          severity: reg.severity === 'critical' ? 'critical' : 'high',
          title: `CIS Regression: ${reg.cisRef} (${reg.title})`,
          message: `Control ${reg.cisRef} regressed from PASS to FAIL. Observed: ${reg.currentValue}`,
          details: { cisRef: reg.cisRef, observed: reg.currentValue },
        })
      }
    }
  } catch {
    // Skip if CIS policies unreadable
  }

  // 4. Sign-in Smart Lockout / Failure Burst (last 60 min)
  try {
    const recentFailures = await graph.listSignInLogs({
      status: 'failure',
      daysBack: 1,
      top: 100,
    })
    rulesEvaluated.push('signin_lockout_spike')
    const oneHourAgo = Date.now() - 60 * 60 * 1000
    const lastHour = recentFailures.items.filter(
      (s) => Date.parse(s.createdDateTime) >= oneHourAgo,
    )
    const lockouts = lastHour.filter((s) => s.status?.errorCode === 50053)
    if (lockouts.length > 0) {
      const affected = Array.from(
        new Set(lockouts.map((l) => l.userPrincipalName || 'unknown')),
      )
      alertsToSend.push({
        ruleKey: 'signin_lockout_spike',
        dedupeKey: `lockout:${affected.sort().join(',')}:${new Date().toISOString().slice(0, 13)}`,
        severity: 'high',
        title: `Entra Smart Lockout Triggered (${lockouts.length} event(s))`,
        message: `Account lockout (AADSTS50053) detected in the past hour for: ${affected.join(', ')}.`,
        details: { lockoutEvents: lockouts.length, users: affected },
      })
    } else if (lastHour.length >= 15) {
      alertsToSend.push({
        ruleKey: 'signin_lockout_spike',
        dedupeKey: `fail_burst:${new Date().toISOString().slice(0, 13)}`,
        severity: 'medium',
        title: `Sign-in Failure Spike (${lastHour.length} failures in 1h)`,
        message: `Observed ${lastHour.length} failed sign-in attempts across the tenant in the last 60 minutes.`,
        details: { failuresLastHour: lastHour.length },
      })
    }
  } catch {
    // Skip if AuditLog.Read.All isn't granted
  }

  let alertsTriggered = 0
  let alertsSkippedDedupe = 0

  for (const alert of alertsToSend) {
    const res = await recordAndDispatchAlert(alert, { fetchImpl })
    if (res.skipped) alertsSkippedDedupe++
    else alertsTriggered++
  }

  return {
    checkedAt: new Date().toISOString(),
    alertsTriggered,
    alertsSkippedDedupe,
    rulesEvaluated,
  }
}

/**
 * Invoked by Cloudflare Cron Trigger (`triggers.crons` in wrangler.jsonc).
 */
export async function runScheduledAlertSweep(): Promise<AlertRunSummary | null> {
  const readiness = await getEffectiveConfigReadiness()
  if (!readiness.graphConfigured) return null
  const db = getDb()
  const hasEnabledHook = await db
    .select()
    .from(alertWebhooks)
    .where(eq(alertWebhooks.enabled, 1))
    .limit(1)
    .get()
  if (!hasEnabledHook) return null
  return runAutomatedAlertChecks()
}
