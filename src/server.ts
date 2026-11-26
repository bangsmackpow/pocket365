import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { useNitroHooks } from 'nitro/app'
import {
  setActiveWaitUntil,
  type CloudflareEnv,
  type Pocket365QueueMessage,
} from '~/server/cf/env'
import {
  handleCloudflareQueue,
  handleCloudflareScheduled,
} from '~/server/cf/handlers'
import {
  getClientIp,
  getForwardedHost,
  getForwardedProto,
} from '~/server/http/proxy'
import {
  verifyCsrfRequest,
  withSecurityHeaders,
} from '~/server/security/headers'
import {
  checkRateLimitAsync,
  rateLimitResponse,
} from '~/server/security/rate-limit'

// Register Cloudflare Workers Cron Trigger & Queue hooks via Nitro v3 runtime
try {
  const hooks = useNitroHooks() as unknown as {
    hook?: (name: string, fn: (ctx: unknown) => Promise<void> | void) => void
  }
  hooks.hook?.('cloudflare:scheduled', async (ctx) => {
    const payload = ctx as {
      controller?: ScheduledController
      env?: CloudflareEnv
    }
    await handleCloudflareScheduled({
      controller: payload.controller,
      env: payload.env,
    })
  })
  hooks.hook?.('cloudflare:queue', async (ctx) => {
    const payload = ctx as {
      batch?: MessageBatch<Pocket365QueueMessage>
    }
    if (payload.batch) {
      await handleCloudflareQueue(payload.batch)
    }
  })
} catch {
  // Outside active Nitro runtime (e.g. unit tests)
}

/**
 * Reconstructs the request URL when forwarded headers are present.
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
    const cfRequest = request as Request & {
      waitUntil?: (promise: Promise<unknown>) => void
    }
    setActiveWaitUntil(cfRequest.waitUntil ?? null)

    try {
      const normalizedReq = withForwardedUrl(request)
      const url = new URL(normalizedReq.url)
      const pathname = url.pathname

      // 0. Disallow automated search/crawler indexing of this private admin console
      if (pathname === '/robots.txt' && normalizedReq.method === 'GET') {
        return withSecurityHeaders(
          new Response('User-agent: *\nDisallow: /\n', {
            status: 200,
            headers: {
              'Content-Type': 'text/plain; charset=utf-8',
              'Cache-Control': 'public, max-age=3600',
            },
          }),
          normalizedReq,
        )
      }

      const clientIp =
        normalizedReq.headers.get('cf-connecting-ip') ||
        getClientIp(normalizedReq) ||
        'local'

      // 1. Layered Edge Rate Limiting on Auth & API routes (excluding /api/health probe)
      if (pathname.startsWith('/api/auth/')) {
        const rl = await checkRateLimitAsync('auth', clientIp)
        if (!rl.allowed) {
          return withSecurityHeaders(rateLimitResponse(rl), normalizedReq)
        }
      } else if (pathname.startsWith('/api/') && pathname !== '/api/health') {
        const rl = await checkRateLimitAsync('api', clientIp)
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
    } finally {
      setActiveWaitUntil(null)
    }
  },
})
