import { createFileRoute } from '@tanstack/react-router'
import { completeOidcCallback } from '~/server/auth/oidc'
import { resolveUserRole } from '~/server/auth/roles'
import {
  buildClearOidcCookieHeader,
  buildSessionCookieHeader,
  createSession,
  OIDC_COOKIE_NAME,
} from '~/server/auth/session'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import type { UserRole } from '~/server/db/schema'
import { getGraphClient } from '~/server/graph/client'
import {
  buildCanonicalUrl,
  getClientIp,
  parseCookies,
} from '~/server/http/proxy'
import {
  DEFAULT_ORG_ID,
  findOrCreateOrgForEntraTenant,
} from '~/server/orgs/service'
import { ensurePrimaryTenantSeeded } from '~/server/tenants/registry'
import {
  getEffectiveConfigReadiness,
  getEffectiveEntraConfig,
} from '~/server/setup/service'

function redirectWithClearOidc(path: string, request: Request): Response {
  const headers = new Headers({
    Location: buildCanonicalUrl(path, request),
    'Cache-Control': 'no-store',
  })
  headers.append('Set-Cookie', buildClearOidcCookieHeader(request))
  return new Response(null, { status: 302, headers })
}

export const Route = createFileRoute('/api/auth/callback')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url)
        const errorParam = url.searchParams.get('error')
        const errorDesc = url.searchParams.get('error_description')
        const ipAddress = getClientIp(request)

        if (errorParam) {
          await recordAuditLog({
            actorOid: 'unknown',
            actorUpn: 'unknown',
            actorRole: 'none',
            action: 'auth.login.error',
            target: 'entra_oidc',
            status: 'failure',
            details: { error: errorParam, description: errorDesc ?? '' },
            ipAddress,
          })
          return redirectWithClearOidc(
            `/login?error=oidc_error&detail=${encodeURIComponent(errorDesc || errorParam)}`,
            request,
          )
        }

        if (url.searchParams.get('admin_consent') === 'True') {
          return redirectWithClearOidc('/admin?consented=true', request)
        }

        const code = url.searchParams.get('code') ?? ''
        const state = url.searchParams.get('state') ?? ''
        const cookies = parseCookies(request.headers.get('cookie'))
        const cookieBindingToken = cookies[OIDC_COOKIE_NAME] ?? ''

        if (!code || !state) {
          return redirectWithClearOidc('/login?error=state_mismatch', request)
        }

        try {
          const cfg = getConfig()
          const identity = await completeOidcCallback({
            code,
            state,
            cookieBindingToken,
            request,
          })

          let organizationId = DEFAULT_ORG_ID
          let role: UserRole | null = null
          let groups = identity.groups
          let redirectTarget = identity.returnTo

          if (cfg.deploymentMode === 'saas') {
            // SaaS Mode: Auto-provision isolated organization keyed by user's home Entra tenant ID
            const { org, created } = await findOrCreateOrgForEntraTenant({
              homeEntraTenantId: identity.tenantId,
              ownerUpn: identity.upn,
            })
            organizationId = org.id
            await ensurePrimaryTenantSeeded(org.id)

            // Organization creator / owner gets 'owner'; other org members default to configured RBAC or 'admin'
            if (org.ownerUpn.toLowerCase() === identity.upn.toLowerCase()) {
              role = 'owner'
            } else {
              role =
                resolveUserRole({
                  oid: identity.oid,
                  preferredUsername: identity.preferredUsername,
                  upn: identity.upn,
                  email: identity.email,
                  groups,
                }) ?? 'admin'
            }

            if (created && redirectTarget === '/') {
              redirectTarget = '/billing?welcome=1'
            }
          } else {
            // Self-Hosted Single-Tenant Mode: strict env + /setup wizard RBAC enforcement
            const [effective, readiness] = await Promise.all([
              getEffectiveEntraConfig(),
              getEffectiveConfigReadiness(),
            ])
            if (
              (identity.hasGroupsOverage || groups.length === 0) &&
              readiness.graphConfigured
            ) {
              try {
                const graph = await getGraphClient()
                groups = await graph.getUserMemberGroupIds(identity.oid)
              } catch {
                // Proceed with token claims if Graph group lookup is unavailable
              }
            }

            role = resolveUserRole({
              oid: identity.oid,
              preferredUsername: identity.preferredUsername,
              upn: identity.upn,
              email: identity.email,
              groups,
            })

            if (!role && effective.source === 'd1_setup') {
              const candidates = new Set(
                [
                  identity.oid,
                  identity.preferredUsername,
                  identity.upn,
                  identity.email,
                  ...groups,
                ]
                  .filter((v): v is string => Boolean(v))
                  .map((v) => v.toLowerCase()),
              )
              if (effective.ownerEntries.some((e) => candidates.has(e))) {
                role = 'owner'
              } else if (effective.adminEntries.some((e) => candidates.has(e))) {
                role = 'admin'
              }
            }
          }

          if (!role) {
            await recordAuditLog({
              organizationId,
              actorOid: identity.oid,
              actorUpn: identity.upn,
              actorRole: 'none',
              action: 'auth.login.denied',
              target: 'pocket365',
              status: 'failure',
              details: {
                reason:
                  'User not in ADMIN_OIDS_OR_GROUPS or VIEWER_OIDS_OR_GROUPS',
                groupCount: groups.length,
              },
              ipAddress,
            })
            return redirectWithClearOidc('/login?error=unauthorized', request)
          }

          const { rawToken } = await createSession({
            organizationId,
            userOid: identity.oid,
            userUpn: identity.upn,
            displayName: identity.displayName,
            role,
            groups,
            ipAddress,
            userAgent: request.headers.get('user-agent'),
          })

          await recordAuditLog({
            organizationId,
            actorOid: identity.oid,
            actorUpn: identity.upn,
            actorRole: role,
            action: 'auth.login.success',
            target: 'pocket365',
            status: 'success',
            details: {
              role,
              groupCount: groups.length,
              deploymentMode: cfg.deploymentMode,
              homeTenantId: identity.tenantId,
            },
            ipAddress,
          })

          const headers = new Headers({
            Location: buildCanonicalUrl(redirectTarget, request),
            'Cache-Control': 'no-store',
          })
          headers.append('Set-Cookie', buildClearOidcCookieHeader(request))
          headers.append('Set-Cookie', buildSessionCookieHeader(rawToken, request))

          return new Response(null, { status: 302, headers })
        } catch (err) {
          const message =
            err instanceof Error
              ? err.message
              : 'Authentication callback failed.'
          await recordAuditLog({
            actorOid: 'unknown',
            actorUpn: 'unknown',
            actorRole: 'none',
            action: 'auth.login.failed',
            target: 'entra_oidc',
            status: 'failure',
            details: { message },
            ipAddress,
          })
          return redirectWithClearOidc(
            `/login?error=callback_failed&detail=${encodeURIComponent(message)}`,
            request,
          )
        }
      },
    },
  },
})
