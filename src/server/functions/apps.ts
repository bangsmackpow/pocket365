import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { putExportObject } from '~/server/cf/r2'
import { recordAuditLog } from '~/server/db/audit'
import { getGraphClient } from '~/server/graph/client'
import { buildOrgExportKey } from '~/server/orgs/service'
import {
  analyzeAppCredentials,
  analyzeOAuthGrants,
  classifyStaleAccounts,
  type AnalyzedOAuthGrant,
  type AppCredentialFinding,
  type StaleAccountRow,
} from '~/server/graph/insights-helpers'
import {
  classifyGraphError,
  type FriendlyGraphError,
} from '~/server/graph/signin-errors'
import { getClientIp } from '~/server/http/proxy'

export const listAppsAndGrantsFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    await requireSession()
    const graph = await getGraphClient()

    const [appsOutcome, grantsOutcome] = await Promise.all([
      graph
        .listApplications(150)
        .then((apps) => ({
          appCount: apps.length,
          credentials: analyzeAppCredentials(apps),
          error: null as FriendlyGraphError | null,
        }))
        .catch((err) => ({
          appCount: 0,
          credentials: [] as AppCredentialFinding[],
          error: classifyGraphError(err, ['Application.Read.All']) as FriendlyGraphError | null,
        })),
      Promise.all([
        graph.listOAuth2PermissionGrants(150),
        graph.listServicePrincipalsLite(300).catch(() => []),
      ])
        .then(([rawGrants, sps]) => {
          const spMap = new Map(sps.map((sp) => [sp.id, sp.displayName]))
          return {
            grants: analyzeOAuthGrants(rawGrants, spMap),
            error: null as FriendlyGraphError | null,
          }
        })
        .catch((err) => ({
          grants: [] as AnalyzedOAuthGrant[],
          error: classifyGraphError(err, [
            'DelegatedPermissionGrant.ReadWrite.All',
            'Directory.Read.All',
          ]) as FriendlyGraphError | null,
        })),
    ])

    return {
      appCount: appsOutcome.appCount,
      credentials: appsOutcome.credentials,
      appsError: appsOutcome.error,
      grants: grantsOutcome.grants,
      grantsError: grantsOutcome.error,
      summary: {
        expired: appsOutcome.credentials.filter((c) => c.state === 'expired').length,
        critical: appsOutcome.credentials.filter((c) => c.state === 'critical').length,
        warning: appsOutcome.credentials.filter((c) => c.state === 'warning').length,
        highRiskGrants: grantsOutcome.grants.filter((g) => g.isHighRisk).length,
      },
    }
  },
)

const revokeGrantSchema = z.object({
  grantId: z.string().min(1),
  clientDisplayName: z.string().min(1),
  scopes: z.array(z.string()),
})

export const revokeOAuthGrantFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => revokeGrantSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'oauth.revoke_grant')
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      await graph.deleteOAuth2PermissionGrant(data.grantId)
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'oauth.revoke_grant',
        target: data.clientDisplayName,
        status: 'success',
        details: { grantId: data.grantId, scopes: data.scopes },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'oauth.revoke_grant',
        target: data.clientDisplayName,
        status: 'failure',
        details: {
          grantId: data.grantId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

const staleAuditSchema = z.object({
  staleDays: z.number().int().min(7).max(365).default(30),
})

export const getStaleAccountsAuditFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => staleAuditSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    await requireSession()
    const graph = await getGraphClient()

    try {
      const [{ users, hasSignInActivityField }, skus] = await Promise.all([
        graph.listUsersForStaleAudit(250),
        graph.listSubscribedSkus().catch(() => []),
      ])

      const signInMap = new Map<string, string>()
      if (!hasSignInActivityField) {
        try {
          const recentSignIns = await graph.listSignInLogs({
            daysBack: 7,
            top: 200,
          })
          for (const s of recentSignIns.items) {
            if (s.userId && !signInMap.has(s.userId)) {
              signInMap.set(s.userId, s.createdDateTime)
            }
            if (s.userPrincipalName) {
              const key = s.userPrincipalName.toLowerCase()
              if (!signInMap.has(key)) {
                signInMap.set(key, s.createdDateTime)
              }
            }
          }
        } catch {
          // Optional fallback when AuditLog.Read.All is unavailable
        }
      }

      const rows: StaleAccountRow[] = classifyStaleAccounts(
        users,
        data.staleDays,
        signInMap,
      )

      return {
        ok: true as const,
        hasSignInActivityField,
        rows,
        skus,
        summary: {
          totalUsers: rows.length,
          disabledWithLicense: rows.filter((r) =>
            r.flags.includes('disabled_with_license'),
          ).length,
          staleLicensed: rows.filter((r) => r.flags.includes('stale_licensed'))
            .length,
          totalGuests: rows.filter((r) => r.userType === 'Guest').length,
          staleGuests: rows.filter((r) => r.flags.includes('stale_guest'))
            .length,
        },
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        hasSignInActivityField: false,
        rows: [] as StaleAccountRow[],
        skus: [],
        summary: {
          totalUsers: 0,
          disabledWithLicense: 0,
          staleLicensed: 0,
          totalGuests: 0,
          staleGuests: 0,
        },
        error: classifyGraphError(err, ['User.ReadWrite.All', 'AuditLog.Read.All']),
      }
    }
  })

const uarCertifySchema = z.object({
  staleDays: z.number().int().min(7).max(365).default(90),
  attestationNotes: z.string().max(500).optional(),
})

export const certifyUserAccessReviewFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => uarCertifySchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'uar.certify')
    const graph = await getGraphClient()
    const [{ users }, directoryRoles] = await Promise.all([
      graph.listUsersForStaleAudit(250),
      graph.listDirectoryRolesWithMembers().catch(() => []),
    ])

    const now = Date.now()
    const id = crypto.randomUUID()
    const ipAddress = getClientIp(getRequest())

    const staleThresholdMs = now - data.staleDays * 86_400_000
    const dormantUsers = users.filter((u) => {
      const last = u.signInActivity?.lastSignInDateTime
      if (!last) return false
      return new Date(last).getTime() < staleThresholdMs
    })

    const guestAccounts = users.filter((u) => u.userType === 'Guest')
    const globalAdmins =
      directoryRoles
        .find((r) => r.displayName === 'Global Administrator')
        ?.members?.length ?? 0

    const uarPayload = {
      id,
      organizationId: session.organizationId,
      certifiedAt: new Date(now).toISOString(),
      attestation: {
        certifiedByUpn: session.upn,
        certifiedByRole: session.role,
        statement:
          'I certify that I have reviewed the active workforce users, privileged directory administrators, and external guest accounts for this organization, and verified that access permissions adhere to the principle of least privilege in accordance with SOC 2 CC6.2, CC6.3 and ISO/IEC 27001:2022 A.5.18.',
        notes:
          data.attestationNotes ||
          'Periodic Quarterly User Access Review completed.',
      },
      metrics: {
        totalAccountsReviewed: users.length,
        dormantAccountsIdentified: dormantUsers.length,
        guestAccountsReviewed: guestAccounts.length,
        globalAdminsCount: globalAdmins,
        staleThresholdDays: data.staleDays,
      },
      privilegedRoles: directoryRoles.map((r) => ({
        role: r.displayName,
        memberCount: r.members?.length ?? 0,
      })),
    }

    const r2Key = buildOrgExportKey(
      session.organizationId,
      'uar',
      `uar-certification-${id}.json`,
    )

    await putExportObject({
      key: r2Key,
      body: JSON.stringify(uarPayload, null, 2),
      contentType: 'application/json',
      customMetadata: {
        organizationId: session.organizationId,
        certifiedBy: session.upn,
        totalReviewed: String(users.length),
      },
    })

    await recordAuditLog({
      organizationId: session.organizationId,
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'uar.certify',
      target: id,
      status: 'success',
      details: {
        r2Key,
        totalAccountsReviewed: users.length,
        dormantAccounts: dormantUsers.length,
        notes: data.attestationNotes,
      },
      ipAddress,
    })

    return {
      ok: true,
      id,
      r2Key,
      certifiedAt: uarPayload.certifiedAt,
      metrics: uarPayload.metrics,
      attestation: uarPayload.attestation,
    }
  })
