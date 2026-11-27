import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { requireSession } from '~/server/auth/guards'
import { getConfig } from '~/server/config'
import { getGraphClient, type GraphSignIn } from '~/server/graph/client'
import {
  classifyGraphError,
  diagnoseSignInError,
  POCKET365_GRAPH_PERMISSIONS,
  type FriendlyGraphError,
  type SignInErrorDiagnosis,
} from '~/server/graph/signin-errors'
import { getEffectiveConfigReadiness } from '~/server/setup/service'
import { resolveActiveTenantForSession } from '~/server/tenants/registry'

export interface EnrichedSignIn extends GraphSignIn {
  diagnosis: SignInErrorDiagnosis
}

const listSignInsSchema = z.object({
  status: z.enum(['all', 'failure', 'success', 'mfa', 'blocked']).optional(),
  user: z.string().max(120).optional(),
  app: z.string().max(120).optional(),
  ipAddress: z.string().max(64).optional(),
  errorCode: z.number().int().min(0).optional(),
  daysBack: z.number().int().min(1).max(30).optional(),
  top: z.number().int().min(10).max(200).optional(),
  nextLink: z.string().url().optional(),
})

export const listSignInLogsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listSignInsSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    await requireSession()
    const graph = await getGraphClient()

    try {
      const page = await graph.listSignInLogs({
        status: data.status ?? 'all',
        user: data.user,
        app: data.app,
        ipAddress: data.ipAddress,
        errorCode: data.errorCode,
        daysBack: data.daysBack ?? 7,
        top: data.top ?? 50,
        nextLink: data.nextLink,
      })

      const signIns: EnrichedSignIn[] = page.items.map((item) => ({
        ...item,
        diagnosis: diagnoseSignInError(
          item.status?.errorCode ?? 0,
          item.status?.failureReason,
        ),
      }))

      const failureCount = signIns.filter(
        (s) => (s.status?.errorCode ?? 0) !== 0,
      ).length
      const mfaCount = signIns.filter(
        (s) => s.diagnosis.category === 'mfa',
      ).length
      const uniqueUsers = new Set(
        signIns.map((s) => s.userPrincipalName || s.userId).filter(Boolean),
      ).size
      const uniqueIps = new Set(
        signIns.map((s) => s.ipAddress).filter(Boolean),
      ).size

      const errorCounts = new Map<number, number>()
      for (const s of signIns) {
        const code = s.status?.errorCode ?? 0
        if (code !== 0) {
          errorCounts.set(code, (errorCounts.get(code) ?? 0) + 1)
        }
      }
      let topError: { code: number; aadstsCode: string; count: number; title: string } | null =
        null
      for (const [code, count] of errorCounts.entries()) {
        if (!topError || count > topError.count) {
          const diag = diagnoseSignInError(code)
          topError = {
            code,
            aadstsCode: diag.aadstsCode,
            count,
            title: diag.title,
          }
        }
      }

      return {
        ok: true as const,
        signIns,
        nextLink: page.nextLink,
        summary: {
          total: signIns.length,
          failures: failureCount,
          mfaEvents: mfaCount,
          uniqueUsers,
          uniqueIps,
          topError,
        },
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        signIns: [] as EnrichedSignIn[],
        nextLink: null as string | null,
        summary: {
          total: 0,
          failures: 0,
          mfaEvents: 0,
          uniqueUsers: 0,
          uniqueIps: 0,
          topError: null,
        },
        error: classifyGraphError(err, ['AuditLog.Read.All', 'Directory.Read.All']),
      }
    }
  })

const userSignInsSchema = z.object({
  userIdOrUpn: z.string().min(1),
  top: z.number().int().min(1).max(30).optional(),
})

export const getUserSignInsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => userSignInsSchema.parse(input))
  .handler(async ({ data }) => {
    await requireSession()
    const graph = await getGraphClient()
    try {
      const items = await graph.listUserSignInLogs(
        data.userIdOrUpn,
        data.top ?? 10,
      )
      return {
        ok: true as const,
        signIns: items.map((item) => ({
          ...item,
          diagnosis: diagnoseSignInError(
            item.status?.errorCode ?? 0,
            item.status?.failureReason,
          ),
        })),
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        signIns: [] as EnrichedSignIn[],
        error: classifyGraphError(err, ['AuditLog.Read.All', 'Directory.Read.All']),
      }
    }
  })

export const getGraphPermissionsStatusFn = createServerFn({
  method: 'GET',
}).handler(async () => {
  const session = await requireSession()
  const cfg = getConfig()
  const activeTenant = await resolveActiveTenantForSession(session)
  const tenantId =
    activeTenant?.entraTenantId || cfg.entraTenantId || 'organizations'
  const appBase = cfg.appBaseUrl || 'https://pocket365.builtbyvets.app'
  const redirectUri = `${appBase}/admin`
  const consentUrl = cfg.graphClientId
    ? `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/adminconsent?client_id=${encodeURIComponent(cfg.graphClientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`
    : null

  const readiness = await getEffectiveConfigReadiness()
  if (!readiness.graphConfigured) {
    return {
      tenantId,
      consentUrl,
      error:
        'Microsoft Graph credentials are not configured. Check GRAPH_CLIENT_SECRET or OIDC_CLIENT_SECRET.',
      grantedRoles: [] as string[],
      requirements: POCKET365_GRAPH_PERMISSIONS.map((req) => ({
        ...req,
        granted: false,
      })),
    }
  }

  try {
    const graph = await getGraphClient()
    const grantedRoles = await graph.getGrantedRoles()
    const grantedSet = new Set(grantedRoles.map((r) => r.toLowerCase()))
    return {
      tenantId,
      consentUrl,
      error: null,
      grantedRoles,
      requirements: POCKET365_GRAPH_PERMISSIONS.map((req) => ({
        ...req,
        granted: grantedSet.has(req.permission.toLowerCase()),
      })),
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err)
    return {
      tenantId,
      consentUrl,
      error: errorMsg,
      grantedRoles: [] as string[],
      requirements: POCKET365_GRAPH_PERMISSIONS.map((req) => ({
        ...req,
        granted: false,
      })),
    }
  }
})
