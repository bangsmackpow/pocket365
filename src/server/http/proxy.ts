import { getConfig } from '~/server/config'

function firstHeaderValue(header: string | null | undefined): string {
  if (!header) return ''
  return (header.split(',')[0] ?? '').trim()
}

export function getForwardedProto(request?: Request): string {
  if (!request) return ''
  return firstHeaderValue(request.headers.get('x-forwarded-proto')).toLowerCase()
}

export function getForwardedHost(request?: Request): string {
  if (!request) return ''
  return firstHeaderValue(request.headers.get('x-forwarded-host'))
}

export function getClientIp(request?: Request): string | null {
  if (!request) return null
  const forwardedFor = firstHeaderValue(request.headers.get('x-forwarded-for'))
  if (forwardedFor) return forwardedFor
  const realIp = firstHeaderValue(request.headers.get('x-real-ip'))
  if (realIp) return realIp
  return null
}

/**
 * Determines whether cookies should carry the `Secure` attribute.
 * Returns true if APP_BASE_URL uses https:// OR X-Forwarded-Proto is https
 * (e.g., behind Nginx Proxy Manager with SSL termination) OR the request URL is https.
 */
export function isSecureRequest(request?: Request): boolean {
  const cfg = getConfig()
  if (cfg.appBaseUrl.toLowerCase().startsWith('https://')) {
    return true
  }
  if (getForwardedProto(request) === 'https') {
    return true
  }
  if (request) {
    try {
      const parsed = new URL(request.url)
      if (parsed.protocol === 'https:') {
        return true
      }
    } catch {
      // Ignore malformed request URL
    }
  }
  return false
}

/**
 * Returns the canonical external base URL for OIDC redirects and post-login/logout URLs.
 * Prefers APP_BASE_URL; falls back to X-Forwarded-Proto + X-Forwarded-Host when needed.
 */
export function getCanonicalBaseUrl(request?: Request): string {
  const cfg = getConfig()
  if (cfg.appBaseUrl) {
    return cfg.appBaseUrl
  }
  const proto = getForwardedProto(request) || 'http'
  const host = getForwardedHost(request) || request?.headers.get('host') || `localhost:${cfg.port}`
  return `${proto}://${host}`.replace(/\/+$/, '')
}

export function buildCanonicalUrl(pathname: string, request?: Request): string {
  const base = getCanonicalBaseUrl(request)
  const normalizedPath = pathname.startsWith('/') ? pathname : `/${pathname}`
  return `${base}${normalizedPath}`
}

export function sanitizeReturnTo(raw: string | null | undefined): string {
  if (!raw) return '/'
  const trimmed = raw.trim()
  if (!trimmed.startsWith('/') || trimmed.startsWith('//') || trimmed.includes('\\')) {
    return '/'
  }
  return trimmed
}

export function parseCookies(cookieHeader: string | null | undefined): Record<string, string> {
  const result: Record<string, string> = {}
  if (!cookieHeader) return result

  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const name = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (!name) continue
    try {
      result[name] = decodeURIComponent(value)
    } catch {
      result[name] = value
    }
  }
  return result
}

export interface CookieOptions {
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'Lax' | 'Strict' | 'None'
  path?: string
  maxAge?: number
  expires?: Date
}

export function serializeCookie(
  name: string,
  value: string,
  options: CookieOptions = {},
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`]
  parts.push(`Path=${options.path ?? '/'}`)
  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${Math.floor(options.maxAge)}`)
  }
  if (options.expires) {
    parts.push(`Expires=${options.expires.toUTCString()}`)
  }
  if (options.httpOnly !== false) {
    parts.push('HttpOnly')
  }
  if (options.secure) {
    parts.push('Secure')
  }
  parts.push(`SameSite=${options.sameSite ?? 'Lax'}`)
  return parts.join('; ')
}
