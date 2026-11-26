import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { cisSnapshots } from '~/server/db/schema'
import {
  GUEST_ROLE_IDS,
  type CisRemediationId,
} from '~/server/graph/cis-benchmarks'
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
    requireSession()
    const scan = await collectCisScan()
    const db = getDb()
    const history = db
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
    const session = requireRole('admin', undefined, 'cis.save_snapshot')
    const scan = await collectCisScan()
    const db = getDb()
    const id = crypto.randomUUID()
    const createdAt = Date.now()

    db.insert(cisSnapshots)
      .values({
        id,
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

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'cis.save_snapshot',
      target: id,
      status: 'success',
      details: scan.summary,
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, id, scorePct: scan.summary.scorePct }
  },
)

const REMEDIATION_TO_CHECK_ID: Record<CisRemediationId, string> = {
  enable_security_defaults: 'security_defaults',
  block_user_app_consent: 'user_app_consent',
  disable_user_app_registration: 'user_app_registration',
  disable_user_tenant_creation: 'user_tenant_creation',
  disable_user_security_group_creation: 'user_security_groups',
  restrict_guest_access: 'guest_access_restriction',
  restrict_guest_invites: 'guest_invite_restriction',
  block_msol_powershell: 'block_msol_powershell',
  enable_admin_consent_workflow: 'admin_consent_workflow',
  disable_email_verified_join: 'email_verified_join',
  disable_sms_auth_method: 'auth_disable_sms',
  disable_voice_auth_method: 'auth_disable_voice',
  sp_disable_anonymous_links: 'sp_anonymous_links',
  sp_disable_external_resharing: 'sp_external_resharing',
  sp_block_legacy_auth: 'sp_legacy_auth',
  sp_enable_idle_signout: 'sp_idle_signout',
}

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
    const session = requireRole('admin', undefined, `cis.remediate:${data.remediationId}`)
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    const id: CisRemediationId = data.remediationId
    let summary = ''

    const patchDefaultRolePerms = async (
      updates: NonNullable<
        Awaited<ReturnType<typeof graph.getAuthorizationPolicy>>['defaultUserRolePermissions']
      >,
    ) => {
      const current = await graph.getAuthorizationPolicy()
      await graph.updateAuthorizationPolicy({
        defaultUserRolePermissions: {
          ...(current.defaultUserRolePermissions ?? {}),
          ...updates,
        },
      })
    }

    try {
      switch (id) {
        case 'enable_security_defaults':
          await graph.setSecurityDefaultsEnabled(true)
          summary = 'Enabled Microsoft Entra Security Defaults (CIS 5.2.2.1).'
          break
        case 'block_user_app_consent':
          await patchDefaultRolePerms({
            permissionGrantPoliciesAssigned: [],
          })
          summary = 'Blocked unrestricted user app consent (CIS 5.1.2.1).'
          break
        case 'disable_user_app_registration':
          await patchDefaultRolePerms({
            allowedToCreateApps: false,
          })
          summary = 'Disabled non-admin app registrations (CIS 5.1.2.2).'
          break
        case 'disable_user_tenant_creation':
          await patchDefaultRolePerms({
            allowedToCreateTenants: false,
          })
          summary = 'Blocked non-admin Entra tenant creation (CIS 5.1.2.3).'
          break
        case 'disable_user_security_group_creation':
          await patchDefaultRolePerms({
            allowedToCreateSecurityGroups: false,
          })
          summary = 'Restricted non-admin security group creation (CIS 5.1.2.4).'
          break
        case 'block_msol_powershell':
          await graph.updateAuthorizationPolicy({
            blockMsolPowerShell: true,
          })
          summary = 'Blocked legacy MSOL PowerShell for non-admins (CIS 5.1.2.5).'
          break
        case 'restrict_guest_access':
          await graph.updateAuthorizationPolicy({
            guestUserRoleId: GUEST_ROLE_IDS.RESTRICTED,
          })
          summary = 'Set guest directory access to most restrictive (CIS 5.1.2.6).'
          break
        case 'restrict_guest_invites':
          await graph.updateAuthorizationPolicy({
            allowInvitesFrom: 'adminsAndGuestInviters',
          })
          summary = 'Restricted external guest invitations to admins & Guest Inviters (CIS 5.1.6.2).'
          break
        case 'enable_admin_consent_workflow':
          await graph.setAdminConsentRequestEnabled(true)
          summary = 'Enabled Admin Consent Request Workflow (CIS 5.1.5.2).'
          break
        case 'disable_email_verified_join':
          await graph.updateAuthorizationPolicy({
            allowEmailVerifiedUsersToJoinOrganization: false,
          })
          summary = 'Blocked self-service email-verified tenant join (CIS 5.1.2.7).'
          break
        case 'disable_sms_auth_method':
          await graph.setAuthenticationMethodConfigState('Sms', 'disabled')
          summary = 'Disabled weak SMS authentication method (CIS 5.2.3.2).'
          break
        case 'disable_voice_auth_method':
          await graph.setAuthenticationMethodConfigState('Voice', 'disabled')
          summary = 'Disabled weak Voice authentication method (CIS 5.2.3.3).'
          break
        case 'sp_disable_anonymous_links':
          await graph.updateSharePointSettings({
            sharingCapability: 'externalUserSharingOnly',
          })
          summary = 'Disabled anonymous Anyone sharing links in SharePoint (CIS 7.2.1).'
          break
        case 'sp_disable_external_resharing':
          await graph.updateSharePointSettings({
            isResharingByExternalUsersEnabled: false,
          })
          summary = 'Blocked external guest resharing in SharePoint (CIS 7.2.2).'
          break
        case 'sp_block_legacy_auth':
          await graph.updateSharePointSettings({
            isLegacyAuthProtocolsEnabled: false,
          })
          summary = 'Blocked legacy authentication protocols in SharePoint (CIS 7.2.3).'
          break
        case 'sp_enable_idle_signout':
          await graph.updateSharePointSettings({
            idleSessionSignOut: {
              isEnabled: true,
              warnAfterInSeconds: 3300,
              signOutAfterInSeconds: 3600,
            },
          })
          summary = 'Enabled 60-minute SharePoint idle session sign-out (CIS 7.2.4).'
          break
      }

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

      recordAuditLog({
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
      recordAuditLog({
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
    requireSession()
    const graph = getGraphClient()

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
    requireSession()
    const graph = getGraphClient()

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
        .sort((a, b) => b.members.length - a.members.length || a.displayName.localeCompare(b.displayName))

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
    const session = requireRole('admin', undefined, 'role.add_member')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.addDirectoryRoleMember(data.roleId, data.memberId)
      recordAuditLog({
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
      recordAuditLog({
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
    const session = requireRole('admin', undefined, 'role.remove_member')
    const ipAddress = getClientIp(getRequest())

    if (
      data.memberId.toLowerCase() === session.oid.toLowerCase() &&
      data.roleDisplayName.toLowerCase() === 'global administrator'
    ) {
      throw new Error(
        'Safety check: you cannot remove your own account from Global Administrator inside Pocket365.',
      )
    }

    const graph = getGraphClient()
    try {
      await graph.removeDirectoryRoleMember(data.roleId, data.memberId)
      recordAuditLog({
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
      recordAuditLog({
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
