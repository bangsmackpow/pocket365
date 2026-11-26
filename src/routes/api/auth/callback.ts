import { createFileRoute } from '@tanstack/react-router'
import { completeOidcCallback } from '~/server/auth/oidc'
import { resolveUserRole } from '~/server/auth/roles'
import {
  buildClearOidcCookieHeader,
  buildSessionCookieHeader,
  createSession,
  OIDC_COOKIE_NAME,
} from '~/server/auth/session'
import { getConfigReadiness } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { getGraphClient } from '~/server/graph/client'
import {
  buildCanonicalUrl,
  getClientIp,
  parseCookies,
} from '~/server/http/proxy'

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

        const code = url.searchParams.get('code') ?? ''
        const state = url.searchParams.get('state') ?? ''
        const cookies = parseCookies(request.headers.get('cookie'))
        const cookieBindingToken = cookies[OIDC_COOKIE_NAME] ?? ''

        if (!code || !state) {
          return redirectWithClearOidc('/login?error=state_mismatch', request)
        }

        try {
          const identity = await completeOidcCallback({
            code,
            state,
            cookieBindingToken,
            request,
          })

          // If Entra emitted a group overage claim or omitted groups, resolve via Graph when configured
          let groups = identity.groups
          if (
            (identity.hasGroupsOverage || groups.length === 0) &&
            getConfigReadiness().graphConfigured
          ) {
            try {
              const graph = await getGraphClient()
              groups = await graph.getUserMemberGroupIds(identity.oid)
            } catch {
              // Proceed with token claims if Graph group lookup is unavailable
            }
          }

          const role = resolveUserRole({
            oid: identity.oid,
            preferredUsername: identity.preferredUsername,
            upn: identity.upn,
            email: identity.email,
            groups,
          })

          if (!role) {
            await recordAuditLog({
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
            userOid: identity.oid,
            userUpn: identity.upn,
            displayName: identity.displayName,
            role,
            groups,
            ipAddress,
            userAgent: request.headers.get('user-agent'),
          })

          await recordAuditLog({
            actorOid: identity.oid,
            actorUpn: identity.upn,
            actorRole: role,
            action: 'auth.login.success',
            target: 'pocket365',
            status: 'success',
            details: { role, groupCount: groups.length },
            ipAddress,
          })

          const headers = new Headers({
            Location: buildCanonicalUrl(identity.returnTo, request),
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
