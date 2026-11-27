import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { requireEntitlement } from '~/server/billing/entitlements'
import { putExportObject } from '~/server/cf/r2'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { cisSnapshots } from '~/server/db/schema'
import { buildOrgExportKey } from '~/server/orgs/service'
import {
  type CisRemediationId,
} from '~/server/graph/cis-benchmarks'
import {
  executeCisRemediation,
  REMEDIATION_TO_CHECK_ID,
} from '~/server/graph/cis-remediation'
import { collectCisScan } from '~/server/graph/cis-scanner'
import {
  getGraphClient,
  type GraphDirectoryAudit,
  type GraphDirectoryRole,
} from '~/server/graph/client'
import {
  classifyGraphError,
  type FriendlyGraphError,
} from '~/server/graph/signin-errors'
import { getClientIp } from '~/server/http/proxy'

async function waitMs(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms))
}

export const runCisBenchmarkScanFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    const session = await requireSession()
    const scan = await collectCisScan()
    const db = getDb()
    const history = await db
      .select({
        id: cisSnapshots.id,
        actorUpn: cisSnapshots.actorUpn,
        scorePct: cisSnapshots.scorePct,
        passed: cisSnapshots.passed,
        failed: cisSnapshots.failed,
        warned: cisSnapshots.warned,
        unavailable: cisSnapshots.unavailable,
        createdAt: cisSnapshots.createdAt,
      })
      .from(cisSnapshots)
      .where(eq(cisSnapshots.organizationId, session.organizationId))
      .orderBy(desc(cisSnapshots.createdAt))
      .limit(15)
      .all()

    return {
      ...scan,
      history,
    }
  },
)

export const saveCisSnapshotFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const session = await requireRole('admin', undefined, 'cis.save_snapshot')
    const scan = await collectCisScan()
    const db = getDb()
    const id = crypto.randomUUID()
    const createdAt = Date.now()

    await db
      .insert(cisSnapshots)
      .values({
        id,
        organizationId: session.organizationId,
        actorUpn: session.upn,
        scorePct: scan.summary.scorePct,
        passed: scan.summary.passed,
        failed: scan.summary.failed,
        warned: scan.summary.warned,
        unavailable: scan.summary.unavailable,
        checksJson: JSON.stringify(scan.checks),
        createdAt,
      })
      .run()

    // Archive organization-scoped compliance report JSON to Cloudflare R2
    const r2Key = buildOrgExportKey(
      session.organizationId,
      'cis',
      `cis-report-${id}.json`,
    )
    await putExportObject({
      key: r2Key,
      body: JSON.stringify(
        {
          id,
          organizationId: session.organizationId,
          createdAt: new Date(createdAt).toISOString(),
          actorUpn: session.upn,
          summary: scan.summary,
          checks: scan.checks,
        },
        null,
        2,
      ),
      contentType: 'application/json',
      customMetadata: {
        organizationId: session.organizationId,
        actorUpn: session.upn,
        scorePct: String(scan.summary.scorePct),
      },
    })

    await recordAuditLog({
      organizationId: session.organizationId,
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'cis.save_snapshot',
      target: id,
      status: 'success',
      details: { ...scan.summary, r2Key },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, id, scorePct: scan.summary.scorePct, r2Key }
  },
)

const remediationSchema = z.object({
  remediationId: z.enum([
    'enable_security_defaults',
    'block_user_app_consent',
    'disable_user_app_registration',
    'disable_user_tenant_creation',
    'disable_user_security_group_creation',
    'restrict_guest_access',
    'restrict_guest_invites',
    'block_msol_powershell',
    'enable_admin_consent_workflow',
    'disable_email_verified_join',
    'enable_authenticator_context',
    'disable_sms_auth_method',
    'disable_voice_auth_method',
    'sp_disable_anonymous_links',
    'sp_disable_external_resharing',
    'sp_block_legacy_auth',
    'sp_enable_idle_signout',
  ]),
})

export const applyCisRemediationFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => remediationSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole(
      'admin',
      undefined,
      `cis.remediate:${data.remediationId}`,
    )
    await requireEntitlement('cis.autofix', session)
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    const id: CisRemediationId = data.remediationId

    try {
      const { summary } = await executeCisRemediation(graph, id)

      // Poll Entra briefly for read-after-write replication before returning the refreshed scan
      const targetCheckId = REMEDIATION_TO_CHECK_ID[id]
      let refreshedScan = await collectCisScan()
      for (let attempt = 0; attempt < 3; attempt++) {
        const updatedCheck = refreshedScan.checks.find(
          (c) => c.id === targetCheckId,
        )
        if (updatedCheck?.status === 'pass') {
          break
        }
        await waitMs(1500)
        refreshedScan = await collectCisScan()
      }

      const verifiedPass =
        refreshedScan.checks.find((c) => c.id === targetCheckId)?.status ===
        'pass'

      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `cis.remediate:${id}`,
        target: 'tenant_policy',
        status: 'success',
        details: { remediationId: id, summary, verifiedPass },
        ipAddress,
      })

      return {
        ok: true,
        verifiedPass,
        summary: verifiedPass
          ? summary
          : `${summary} Entra ID may still be replicating this policy change—click Re-scan Tenant in a few seconds if it still shows Failed.`,
        scan: refreshedScan,
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `cis.remediate:${id}`,
        target: 'tenant_policy',
        status: 'failure',
        details: { remediationId: id, error: message },
        ipAddress,
      })
      throw err
    }
  })

const listDirectoryAuditsSchema = z.object({
  category: z.string().max(64).optional(),
  activity: z.string().max(120).optional(),
  daysBack: z.number().int().min(1).max(30).optional(),
  top: z.number().int().min(10).max(200).optional(),
  nextLink: z.string().url().optional(),
})

export const listDirectoryAuditsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listDirectoryAuditsSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    await requireSession()
    const graph = await getGraphClient()

    try {
      const page = await graph.listDirectoryAudits({
        category: data.category,
        activity: data.activity,
        daysBack: data.daysBack ?? 7,
        top: data.top ?? 50,
        nextLink: data.nextLink,
      })
      return {
        ok: true as const,
        audits: page.items,
        nextLink: page.nextLink,
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        audits: [] as GraphDirectoryAudit[],
        nextLink: null as string | null,
        error: classifyGraphError(err, ['AuditLog.Read.All', 'Directory.Read.All']),
      }
    }
  })

export interface EnrichedRoleMember {
  id: string
  displayName: string
  userPrincipalName: string | null
  accountEnabled: boolean | null
  mfaRegistered: boolean | null
}

export interface EnrichedDirectoryRole {
  id: string
  displayName: string
  description: string | null
  roleTemplateId: string | null
  members: EnrichedRoleMember[]
}

export const listPrivilegedRolesFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    await requireSession()
    const graph = await getGraphClient()

    try {
      const [roles, mfaMap] = await Promise.all([
        graph.listDirectoryRolesWithMembers(),
        graph
          .listUserRegistrationDetails({ top: 500 })
          .then((res) => new Map(res.items.map((u) => [u.id, u.isMfaRegistered])))
          .catch(() => new Map<string, boolean>()),
      ])

      const enriched: EnrichedDirectoryRole[] = roles
        .map((r: GraphDirectoryRole) => ({
          id: r.id,
          displayName: r.displayName,
          description: r.description,
          roleTemplateId: r.roleTemplateId,
          members: (r.members ?? []).map((m) => ({
            id: m.id,
            displayName: m.displayName || m.userPrincipalName || m.id,
            userPrincipalName: m.userPrincipalName ?? null,
            accountEnabled: m.accountEnabled ?? null,
            mfaRegistered: mfaMap.has(m.id) ? (mfaMap.get(m.id) ?? null) : null,
          })),
        }))
        .sort(
          (a, b) =>
            b.members.length - a.members.length ||
            a.displayName.localeCompare(b.displayName),
        )

      const globalAdmin = enriched.find(
        (r) =>
          r.roleTemplateId === '62e90394-69f5-4237-9190-012177145e10' ||
          r.displayName.toLowerCase() === 'global administrator',
      )

      const uniqueAdmins = new Map<string, EnrichedRoleMember>()
      for (const role of enriched) {
        for (const m of role.members) {
          uniqueAdmins.set(m.id, m)
        }
      }

      const adminsMissingMfa = Array.from(uniqueAdmins.values()).filter(
        (m) => m.mfaRegistered === false,
      ).length

      return {
        ok: true as const,
        roles: enriched,
        summary: {
          activeRoles: enriched.filter((r) => r.members.length > 0).length,
          totalAssignments: enriched.reduce((sum, r) => sum + r.members.length, 0),
          uniqueAdmins: uniqueAdmins.size,
          globalAdminCount: globalAdmin?.members.length ?? 0,
          adminsMissingMfa,
        },
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        roles: [] as EnrichedDirectoryRole[],
        summary: {
          activeRoles: 0,
          totalAssignments: 0,
          uniqueAdmins: 0,
          globalAdminCount: 0,
          adminsMissingMfa: 0,
        },
        error: classifyGraphError(err, [
          'RoleManagement.ReadWrite.Directory',
          'Directory.Read.All',
        ]),
      }
    }
  },
)

const modifyRoleMemberSchema = z.object({
  roleId: z.string().min(1),
  roleDisplayName: z.string().min(1),
  memberId: z.string().min(1),
  memberLabel: z.string().min(1),
})

export const addRoleMemberFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => modifyRoleMemberSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'role.add_member')
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      await graph.addDirectoryRoleMember(data.roleId, data.memberId)
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'role.add_member',
        target: `${data.roleDisplayName} <- ${data.memberLabel}`,
        status: 'success',
        details: { roleId: data.roleId, memberId: data.memberId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'role.add_member',
        target: `${data.roleDisplayName} <- ${data.memberLabel}`,
        status: 'failure',
        details: {
          roleId: data.roleId,
          memberId: data.memberId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

export const removeRoleMemberFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => modifyRoleMemberSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'role.remove_member')
    const ipAddress = getClientIp(getRequest())

    if (
      data.memberId.toLowerCase() === session.oid.toLowerCase() &&
      data.roleDisplayName.toLowerCase() === 'global administrator'
    ) {
      throw new Error(
        'Safety check: you cannot remove your own account from Global Administrator inside Pocket365.',
      )
    }

    const graph = await getGraphClient()
    try {
      await graph.removeDirectoryRoleMember(data.roleId, data.memberId)
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'role.remove_member',
        target: `${data.roleDisplayName} -/-> ${data.memberLabel}`,
        status: 'success',
        details: { roleId: data.roleId, memberId: data.memberId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'role.remove_member',
        target: `${data.roleDisplayName} -/-> ${data.memberLabel}`,
        status: 'failure',
        details: {
          roleId: data.roleId,
          memberId: data.memberId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })
