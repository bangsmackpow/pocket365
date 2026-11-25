import handler, { createServerEntry } from '@tanstack/react-start/server-entry'
import { getDb } from '~/server/db'
import { ensureJobWorkerStarted } from '~/server/graph/jobs'
import { getForwardedHost, getForwardedProto } from '~/server/http/proxy'

// Ensure SQLite schema migrations and background job worker initialize on startup
try {
  getDb()
  ensureJobWorkerStarted()
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
  fetch(request) {
    return handler.fetch(withForwardedUrl(request))
  },
})
