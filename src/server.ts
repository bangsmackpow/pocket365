import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { ensureAlertSchedulerStarted } from '~/server/alerts/engine'
import { getDb } from '~/server/db'
import { ensureJobWorkerStarted } from '~/server/graph/jobs'
import {
  getClientIp,
  getForwardedHost,
  getForwardedProto,
} from '~/server/http/proxy'
import {
  verifyCsrfRequest,
  withSecurityHeaders,
} from '~/server/security/headers'
import { checkRateLimit, rateLimitResponse } from '~/server/security/rate-limit'

// Ensure SQLite schema migrations, background job worker, and alert scheduler initialize on startup
try {
  getDb()
  ensureJobWorkerStarted()
  ensureAlertSchedulerStarted()
} catch (err) {
  console.error('[pocket365] Startup initialization warning:', err)
}

/**
 * Reconstructs the request URL using X-Forwarded-Proto and X-Forwarded-Host
 * when running behind Nginx Proxy Manager so downstream handlers observe
 * the accurate external scheme and host.
 */
function withForwardedUrl(request: Request): Request {
  const forwardedProto = getForwardedProto(request)
  const forwardedHost = getForwardedHost(request)

  if (!forwardedProto && !forwardedHost) {
    return request
  }

  try {
    const currentUrl = new URL(request.url)
    const nextProto =
      forwardedProto === 'https' || forwardedProto === 'http'
        ? `${forwardedProto}:`
        : currentUrl.protocol
    const nextHost = forwardedHost || currentUrl.host

    if (nextProto === currentUrl.protocol && nextHost === currentUrl.host) {
      return request
    }

    const updatedUrl = new URL(request.url)
    updatedUrl.protocol = nextProto
    updatedUrl.host = nextHost

    const init: RequestInit & { duplex?: 'half' } = {
      method: request.method,
      headers: request.headers,
      redirect: request.redirect,
    }
    if (request.method !== 'GET' && request.method !== 'HEAD' && request.body) {
      init.body = request.body
      init.duplex = 'half'
    }

    return new Request(updatedUrl.toString(), init)
  } catch {
    return request
  }
}

export default createServerEntry({
  async fetch(request) {
    const normalizedReq = withForwardedUrl(request)
    const url = new URL(normalizedReq.url)
    const pathname = url.pathname
    const clientIp = getClientIp(normalizedReq) || 'local'

    // 1. Layered Rate Limiting on Auth & API routes (excluding /api/health probe)
    if (pathname.startsWith('/api/auth/')) {
      const rl = checkRateLimit('auth', clientIp)
      if (!rl.allowed) {
        return withSecurityHeaders(rateLimitResponse(rl), normalizedReq)
      }
    } else if (pathname.startsWith('/api/') && pathname !== '/api/health') {
      const rl = checkRateLimit('api', clientIp)
      if (!rl.allowed) {
        return withSecurityHeaders(rateLimitResponse(rl), normalizedReq)
      }
    }

    // 2. CSRF Origin & Fetch-Metadata enforcement on all mutating requests
    const csrf = verifyCsrfRequest(normalizedReq)
    if (!csrf.ok) {
      return withSecurityHeaders(
        Response.json(
          { error: 'CSRF_FORBIDDEN', message: csrf.reason },
          { status: 403 },
        ),
        normalizedReq,
      )
    }

    // 3. Dispatch to TanStack Start & apply HTTP security headers
    const response = await handler.fetch(normalizedReq)
    return withSecurityHeaders(response, normalizedReq)
  },
})
