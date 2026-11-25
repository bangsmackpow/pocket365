import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { recordAuditLog } from '~/server/db/audit'
import { getGraphClient } from '~/server/graph/client'
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
    requireSession()
    const graph = getGraphClient()

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
    const session = requireRole('admin', undefined, 'oauth.revoke_grant')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.deleteOAuth2PermissionGrant(data.grantId)
      recordAuditLog({
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
      recordAuditLog({
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
    requireSession()
    const graph = getGraphClient()

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
