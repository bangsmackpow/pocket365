import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AuthHttpError, requireCapability, requireRole } from '~/server/auth/guards'
import { resolveUserRole } from '~/server/auth/roles'
import { createSession, SESSION_COOKIE_NAME } from '~/server/auth/session'
import { resetConfigCache } from '~/server/config'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import { decryptSecret, encryptSecret, isEncryptedValue } from './crypto'
import { sanitizeCsvCell } from './csv'
import { verifyCsrfRequest, withSecurityHeaders } from './headers'
import { checkRateLimit, resetRateLimiterForTests } from './rate-limit'
import { assertSafeWebhookUrl, isPrivateOrReservedIp } from './ssrf'

describe('Phase 2 Security Controls', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      APP_BASE_URL: 'https://pocket365.example.com',
      SESSION_SECRET: 'super-secret-session-key-at-least-32-characters-long',
      DATA_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      OWNER_OIDS_OR_GROUPS: 'owner@contoso.com',
      ADMIN_OIDS_OR_GROUPS: 'admin@contoso.com',
      HELPDESK_OIDS_OR_GROUPS: 'helpdesk@contoso.com',
      AUDITOR_OIDS_OR_GROUPS: 'auditor@contoso.com',
      VIEWER_OIDS_OR_GROUPS: 'viewer@contoso.com',
    }
    resetConfigCache()
    resetRateLimiterForTests()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('enforces sliding-window rate limits and reports Retry-After', () => {
    const t0 = 1_000_000
    expect(checkRateLimit('auth', '1.2.3.4', { limit: 2, windowMs: 60_000 }, t0).allowed).toBe(true)
    expect(checkRateLimit('auth', '1.2.3.4', { limit: 2, windowMs: 60_000 }, t0 + 1000).allowed).toBe(true)
    const blocked = checkRateLimit('auth', '1.2.3.4', { limit: 2, windowMs: 60_000 }, t0 + 2000)
    expect(blocked.allowed).toBe(false)
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0)

    expect(checkRateLimit('auth', '1.2.3.4', { limit: 2, windowMs: 60_000 }, t0 + 61_000).allowed).toBe(true)
  })

  it('encrypts and decrypts secrets with AES-256-GCM and detects tampering', () => {
    const secret = 'https://hooks.slack.com/services/T000/B000/SECRET'
    const encrypted = encryptSecret(secret)
    expect(isEncryptedValue(encrypted)).toBe(true)
    expect(encrypted).not.toContain('hooks.slack.com')
    expect(decryptSecret(encrypted)).toBe(secret)

    expect(decryptSecret('legacy-plain')).toBe('legacy-plain')

    const tampered = `${encrypted.slice(0, -2)}AA`
    expect(() => decryptSecret(tampered)).toThrow()
  })

  it('blocks SSRF targets (private IPs, loopback, metadata, non-HTTPS) and allows public HTTPS', async () => {
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true)
    expect(isPrivateOrReservedIp('10.0.0.5')).toBe(true)
    expect(isPrivateOrReservedIp('172.18.0.2')).toBe(true)
    expect(isPrivateOrReservedIp('192.168.1.10')).toBe(true)
    expect(isPrivateOrReservedIp('::1')).toBe(true)
    expect(isPrivateOrReservedIp('::ffff:127.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false)

    await expect(assertSafeWebhookUrl('http://127.0.0.1:3000/hook')).rejects.toThrow()
    await expect(assertSafeWebhookUrl('https://169.254.169.254/latest')).rejects.toThrow()
    await expect(assertSafeWebhookUrl('https://localhost/hook')).rejects.toThrow()
    await expect(
      assertSafeWebhookUrl('https://internal.example.com/hook', {
        lookup: async () => [{ address: '10.1.2.3', family: 4 }],
      }),
    ).rejects.toThrow(/SSRF/i)

    const safe = await assertSafeWebhookUrl('https://hooks.example.com/hook', {
      lookup: async () => [{ address: '93.184.216.34', family: 4 }],
    })
    expect(safe.hostname).toBe('hooks.example.com')
  })

  it('enforces CSRF Origin & Fetch-Metadata and applies HTTP security headers', () => {
    const badOrigin = new Request('https://pocket365.example.com/api/auth/logout', {
      method: 'POST',
      headers: { origin: 'https://evil.example.net' },
    })
    expect(verifyCsrfRequest(badOrigin).ok).toBe(false)

    const crossSite = new Request('https://pocket365.example.com/api/auth/logout', {
      method: 'POST',
      headers: { 'sec-fetch-site': 'cross-site' },
    })
    expect(verifyCsrfRequest(crossSite).ok).toBe(false)

    const goodReq = new Request('https://pocket365.example.com/api/auth/logout', {
      method: 'POST',
      headers: {
        origin: 'https://pocket365.example.com',
        'sec-fetch-site': 'same-origin',
      },
    })
    expect(verifyCsrfRequest(goodReq).ok).toBe(true)

    const secured = withSecurityHeaders(new Response('ok'), goodReq)
    expect(secured.headers.get('X-Frame-Options')).toBe('DENY')
    expect(secured.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(secured.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'")
    expect(secured.headers.get('Strict-Transport-Security')).toContain('max-age=')
  })

  it('neutralizes CSV formula injection payloads', () => {
    expect(sanitizeCsvCell('=cmd|"/C calc"!A0')).toBe('"\'=cmd|""/C calc""!A0"')
    expect(sanitizeCsvCell('+SUM(A1:A5)')).toBe("'+SUM(A1:A5)")
    expect(sanitizeCsvCell('@evil()')).toBe("'@evil()")
    expect(sanitizeCsvCell('normal@contoso.com')).toBe('normal@contoso.com')
  })

  it('enforces 5-tier granular RBAC capabilities cleanly', async () => {
    expect(resolveUserRole({ oid: '1', preferredUsername: 'owner@contoso.com' })).toBe('owner')
    expect(resolveUserRole({ oid: '2', preferredUsername: 'helpdesk@contoso.com' })).toBe('helpdesk')
    expect(resolveUserRole({ oid: '3', preferredUsername: 'auditor@contoso.com' })).toBe('security_auditor')

    const { rawToken: hdToken } = await createSession({
      userOid: 'hd-1',
      userUpn: 'helpdesk@contoso.com',
      displayName: 'Helpdesk Tech',
      role: 'helpdesk',
      groups: [],
    })
    const hdReq = new Request('https://pocket365.example.com/users', {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${hdToken}` },
    })

    expect((await requireCapability('helpdesk.actions', hdReq)).role).toBe('helpdesk')
    await expect(requireRole('admin', hdReq, 'cis.remediate')).rejects.toThrowError(
      AuthHttpError,
    )
  })
})
