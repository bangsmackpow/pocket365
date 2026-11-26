import { getCanonicalBaseUrl, isSecureRequest } from '~/server/http/proxy'

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * Verifies Origin / Sec-Fetch-Site headers on mutating HTTP requests
 * to defend against cross-site request forgery (CSRF).
 */
export function verifyCsrfRequest(request: Request): {
  ok: boolean
  reason?: string
} {
  const method = request.method.toUpperCase()
  if (!MUTATING_METHODS.has(method)) {
    return { ok: true }
  }

  const pathname = new URL(request.url).pathname
  // Allow external billing webhooks authenticated via cryptographic HMAC signature
  if (pathname === '/api/billing/webhook') {
    return { ok: true }
  }

  const fetchSite = (request.headers.get('sec-fetch-site') || '').toLowerCase()
  if (fetchSite === 'cross-site') {
    return { ok: false, reason: 'Cross-site request blocked by Fetch Metadata policy.' }
  }

  const origin = request.headers.get('origin')
  if (!origin) {
    // Same-origin non-browser or form clients without Origin; allow if Sec-Fetch-Site isn't cross-site
    return { ok: true }
  }

  const expectedOrigin = new URL(getCanonicalBaseUrl(request)).origin
  let requestOrigin = ''
  try {
    requestOrigin = new URL(request.url).origin
  } catch {
    requestOrigin = ''
  }

  if (origin === expectedOrigin || (requestOrigin && origin === requestOrigin)) {
    return { ok: true }
  }

  return {
    ok: false,
    reason: `CSRF origin mismatch: received "${origin}", expected "${expectedOrigin}".`,
  }
}

/**
 * Attaches defense-in-depth HTTP security headers onto every response.
 */
export function withSecurityHeaders(
  response: Response,
  request?: Request,
): Response {
  const headers = new Headers(response.headers)

  if (!headers.has('X-Content-Type-Options')) {
    headers.set('X-Content-Type-Options', 'nosniff')
  }
  if (!headers.has('X-Frame-Options')) {
    headers.set('X-Frame-Options', 'DENY')
  }
  if (!headers.has('X-Robots-Tag')) {
    headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive')
  }
  if (!headers.has('Referrer-Policy')) {
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  }
  if (!headers.has('Permissions-Policy')) {
    headers.set(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=()',
    )
  }
  if (!headers.has('Content-Security-Policy')) {
    headers.set(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self' https://login.microsoftonline.com",
      ].join('; '),
    )
  }
  if (isSecureRequest(request) && !headers.has('Strict-Transport-Security')) {
    headers.set(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
    )
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}
