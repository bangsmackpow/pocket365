import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { getDb } from '~/server/db'
import { listAuditLogs, recordAuditLog } from '~/server/db/audit'
import {
  ignoredActionItems,
  type AuditLogRow,
  type JobRow,
} from '~/server/db/schema'
import {
  getRuntimeSettings,
  runtimeSettingsSchema,
  updateRuntimeSettings,
  type RuntimeSettings,
} from '~/server/db/settings'
import {
  summarizeCisChecks,
  type CisCategory,
  type CisRemediationId,
  type CisSeverity,
} from '~/server/graph/cis-benchmarks'
import { collectCisScan } from '~/server/graph/cis-scanner'
import {
  getGraphClient,
  type GraphOrganization,
  type GraphSubscribedSku,
} from '~/server/graph/client'
import { listJobs } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'
import { DEFAULT_ORG_ID } from '~/server/orgs/service'
import {
  getEffectiveConfigReadiness,
  type ConfigReadiness,
} from '~/server/setup/service'

export interface DashboardActionItem {
  id: string
  actionItemId: string
  title: string
  description: string
  severity: CisSeverity
  category: CisCategory | 'Licensing'
  cisRef?: string
  nistRef?: string
  soc2Ref?: string
  isoRef?: string
  status: 'fail' | 'warn'
  remediationId?: CisRemediationId
  remediationLabel?: string
  linkTo?: string
  isIgnored: boolean
  ignoredReason?: string | null
}

export interface DashboardComplianceSummary {
  cisScorePct: number
  nistScorePct: number
  soc2ScorePct: number
  isoScorePct: number
  passed: number
  failed: number
  warned: number
  evaluated: number
  oneClickFixable: number
}

export interface DashboardMfaSummary {
  adminMfaPct: number
  allUsersMfaPct: number
  weakMfaCount: number
}

export interface DashboardLicenseSummary {
  totalEnabled: number
  totalConsumed: number
  unassignedCount: number
  utilizationPct: number
}

export interface DashboardDataResult {
  readiness: ConfigReadiness
  deploymentMode: 'self_hosted' | 'saas'
  settings: RuntimeSettings
  organization: GraphOrganization | null
  subscribedSkus: GraphSubscribedSku[]
  graphError: string | null
  compliance: DashboardComplianceSummary
  mfa: DashboardMfaSummary
  license: DashboardLicenseSummary
  actionItems: DashboardActionItem[]
  ignoredCount: number
  recentAudits: AuditLogRow[]
  recentJobs: JobRow[]
}

export const getDashboardDataFn = createServerFn({ method: 'GET' }).handler(
  async (): Promise<DashboardDataResult> => {
    const session = await requireSession()
    const orgId = session.organizationId || DEFAULT_ORG_ID
    const db = getDb()

    const [readiness, settings, recentAudits, recentJobs, ignoredRows] =
      await Promise.all([
        getEffectiveConfigReadiness(),
        getRuntimeSettings(),
        listAuditLogs({ limit: 8 }),
        listJobs({ limit: 8 }),
        db
          .select()
          .from(ignoredActionItems)
          .where(eq(ignoredActionItems.organizationId, orgId))
          .all()
          .catch(() => []),
      ])

    const ignoredMap = new Map<string, { reason: string | null }>()
    for (const row of ignoredRows) {
      ignoredMap.set(row.actionItemId, { reason: row.reason })
    }

    let organization: GraphOrganization | null = null
    let subscribedSkus: GraphSubscribedSku[] = []
    let graphError: string | null = null

    let compliance: DashboardComplianceSummary = {
      cisScorePct: 0,
      nistScorePct: 0,
      soc2ScorePct: 0,
      isoScorePct: 0,
      passed: 0,
      failed: 0,
      warned: 0,
      evaluated: 0,
      oneClickFixable: 0,
    }

    const mfa: DashboardMfaSummary = {
      adminMfaPct: 0,
      allUsersMfaPct: 0,
      weakMfaCount: 0,
    }

    const actionItems: DashboardActionItem[] = []

    if (readiness.graphConfigured) {
      try {
        const graph = await getGraphClient()
        const [org, skus, cisScan] = await Promise.all([
          graph.getOrganization().catch(() => null),
          graph.listSubscribedSkus().catch(() => []),
          collectCisScan().catch(() => null),
        ])

        organization = org
        subscribedSkus = skus

        if (cisScan) {
          const sum = summarizeCisChecks(cisScan.checks)
          compliance = {
            cisScorePct: sum.scorePct,
            nistScorePct: sum.scorePct,
            soc2ScorePct: sum.scorePct,
            isoScorePct: sum.scorePct,
            passed: sum.passed,
            failed: sum.failed,
            warned: sum.warned,
            evaluated: sum.evaluated,
            oneClickFixable: sum.oneClickFixable,
          }

          // Build To-Do / Action items from actionable checks
          for (const c of cisScan.checks) {
            if (c.status === 'fail' || c.status === 'warn') {
              const ignoredInfo = ignoredMap.get(c.id)
              actionItems.push({
                id: c.id,
                actionItemId: c.id,
                title: c.title,
                description: c.currentValue || 'Current posture deviates from recommended baseline.',
                severity: c.severity,
                category: c.category,
                cisRef: c.cisRef,
                nistRef: c.nistRef,
                soc2Ref: c.soc2Ref,
                isoRef: c.isoRef,
                status: c.status,
                remediationId: c.remediationId,
                remediationLabel: c.remediationLabel,
                linkTo: c.linkTo,
                isIgnored: Boolean(ignoredInfo),
                ignoredReason: ignoredInfo?.reason ?? null,
              })
            }
          }

          // Compute MFA summary from registrations if available
          if (cisScan.snapshot?.mfaRegistrations) {
            const regs = cisScan.snapshot.mfaRegistrations
            const mfaCapable = regs.filter((u: { isMfaCapable?: boolean }) => Boolean(u.isMfaCapable)).length
            mfa.allUsersMfaPct =
              regs.length > 0 ? Math.round((mfaCapable / regs.length) * 100) : 0
            mfa.adminMfaPct = cisScan.checks.find((c) => c.id === 'admin_mfa')?.status === 'pass' ? 100 : 0
          }
        }
      } catch (err) {
        graphError =
          err instanceof Error
            ? err.message
            : 'Unable to query Microsoft Graph API.'
      }
    } else {
      graphError =
        'Microsoft Graph app-only credentials are not yet configured.'
    }

    // License summary calculations
    let totalEnabled = 0
    let totalConsumed = 0
    for (const sku of subscribedSkus) {
      totalEnabled += sku.prepaidUnits.enabled || 0
      totalConsumed += sku.consumedUnits || 0
    }
    const unassignedCount = Math.max(0, totalEnabled - totalConsumed)
    const utilizationPct =
      totalEnabled > 0 ? Math.round((totalConsumed / totalEnabled) * 100) : 100

    const license: DashboardLicenseSummary = {
      totalEnabled,
      totalConsumed,
      unassignedCount,
      utilizationPct,
    }

    // Sort action items: unignored first, then critical -> high -> medium
    const severityRank: Record<CisSeverity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
    }

    actionItems.sort((a, b) => {
      if (a.isIgnored !== b.isIgnored) return a.isIgnored ? 1 : -1
      return severityRank[a.severity] - severityRank[b.severity]
    })

    return {
      readiness,
      deploymentMode: readiness.deploymentMode,
      settings,
      organization,
      subscribedSkus,
      graphError,
      compliance,
      mfa,
      license,
      actionItems,
      ignoredCount: actionItems.filter((i) => i.isIgnored).length,
      recentAudits,
      recentJobs,
    }
  },
)

const ignoreActionItemSchema = z.object({
  actionItemId: z.string().min(1),
  reason: z.string().max(200).optional(),
})

export const ignoreActionItemFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => ignoreActionItemSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'dashboard.ignore_action_item')
    const orgId = session.organizationId || DEFAULT_ORG_ID
    const db = getDb()
    const now = Date.now()

    await db
      .insert(ignoredActionItems)
      .values({
        id: crypto.randomUUID(),
        organizationId: orgId,
        actionItemId: data.actionItemId.trim(),
        reason: data.reason?.trim() || null,
        ignoredBy: session.upn,
        createdAt: now,
      })
      .onConflictDoNothing()
      .run()

    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'action_item.ignore',
      target: data.actionItemId,
      status: 'success',
      details: { reason: data.reason },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

const unignoreActionItemSchema = z.object({
  actionItemId: z.string().min(1),
})

export const unignoreActionItemFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => unignoreActionItemSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'dashboard.unignore_action_item')
    const orgId = session.organizationId || DEFAULT_ORG_ID
    const db = getDb()

    await db
      .delete(ignoredActionItems)
      .where(
        and(
          eq(ignoredActionItems.organizationId, orgId),
          eq(ignoredActionItems.actionItemId, data.actionItemId.trim()),
        ),
      )
      .run()

    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'action_item.unignore',
      target: data.actionItemId,
      status: 'success',
      details: {},
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

export const updateRuntimeSettingsFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => runtimeSettingsSchema.partial().parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'settings.update')
    const updated = await updateRuntimeSettings(data, session.upn)

    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'settings.update',
      target: 'runtime_settings',
      status: 'success',
      details: updated,
      ipAddress: getClientIp(getRequest()),
    })

    return updated
  })
