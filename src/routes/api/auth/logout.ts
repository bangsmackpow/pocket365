import { createFileRoute } from '@tanstack/react-router'
import {
  buildClearSessionCookieHeader,
  destroySessionFromRequest,
} from '~/server/auth/session'
import { recordAuditLog } from '~/server/db/audit'
import { buildCanonicalUrl, getClientIp } from '~/server/http/proxy'

async function handleLogout(request: Request): Promise<Response> {
  const session = await destroySessionFromRequest(request)
  if (session) {
    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'auth.logout',
      target: 'pocket365',
      status: 'success',
      details: {},
      ipAddress: getClientIp(request),
    })
  }

  const headers = new Headers({
    Location: buildCanonicalUrl('/login', request),
    'Cache-Control': 'no-store',
  })
  headers.append('Set-Cookie', buildClearSessionCookieHeader(request))

  return new Response(null, { status: 302, headers })
}

export const Route = createFileRoute('/api/auth/logout')({
  server: {
    handlers: {
      POST: async ({ request }) => handleLogout(request),
      GET: async ({ request }) => handleLogout(request),
    },
  },
})
