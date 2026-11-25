import { generateKeyPair, SignJWT } from 'jose'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AuthHttpError, guardApiRole, requireRole } from './guards'
import { verifyEntraIdToken } from './oidc'
import { resolveUserRole } from './roles'
import {
  buildOidcCookieHeader,
  buildSessionCookieHeader,
  createSession,
  destroySessionFromRequest,
  getSessionFromRequest,
  SESSION_COOKIE_NAME,
} from './session'
import { resetConfigCache } from '~/server/config'
import { closeDb, initDbForTesting } from '~/server/db'
import { listAuditLogs } from '~/server/db/audit'

const TENANT_ID = '11111111-2222-3333-4444-555555555555'
const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'

describe('Pocket365 Auth, OIDC Verification, Sessions & RBAC', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      ENTRA_TENANT_ID: TENANT_ID,
      OIDC_CLIENT_ID: CLIENT_ID,
      OIDC_CLIENT_SECRET: 'test-secret',
      SESSION_SECRET: 'a-very-long-test-session-secret-at-least-32-chars',
      APP_BASE_URL: 'https://pocket365.example.com',
      ADMIN_OIDS_OR_GROUPS: 'admin@contoso.com,group-admin-id',
      VIEWER_OIDS_OR_GROUPS: 'viewer-oid-123,group-viewer-id',
    }
    resetConfigCache()
    initDbForTesting(':memory:')
  })

  afterEach(() => {
    closeDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('resolves admin, viewer, and rejects unauthorized principals', () => {
    expect(
      resolveUserRole({
        oid: 'any-oid',
        preferredUsername: 'ADMIN@contoso.com',
        groups: [],
      }),
    ).toBe('admin')

    // Admin takes precedence when user is in both groups
    expect(
      resolveUserRole({
        oid: 'viewer-oid-123',
        preferredUsername: 'dual@contoso.com',
        groups: ['group-viewer-id', 'GROUP-ADMIN-ID'],
      }),
    ).toBe('admin')

    expect(
      resolveUserRole({
        oid: 'other-oid',
        preferredUsername: 'reader@contoso.com',
        groups: ['group-viewer-id'],
      }),
    ).toBe('viewer')

    expect(
      resolveUserRole({
        oid: 'stranger-oid',
        preferredUsername: 'stranger@contoso.com',
        groups: ['unrelated-group'],
      }),
    ).toBeNull()
  })

  it('validates Entra ID token signature, iss, aud, tid, and nonce', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256')
    const validJwt = await new SignJWT({
      tid: TENANT_ID,
      oid: 'user-oid-1',
      preferred_username: 'alice@contoso.com',
      name: 'Alice Admin',
      nonce: 'expected-nonce-xyz',
      groups: ['group-admin-id'],
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(`https://login.microsoftonline.com/${TENANT_ID}/v2.0`)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)

    const verified = await verifyEntraIdToken({
      idToken: validJwt,
      expectedNonce: 'expected-nonce-xyz',
      tenantId: TENANT_ID,
      clientId: CLIENT_ID,
      jwks: publicKey,
    })

    expect(verified.oid).toBe('user-oid-1')
    expect(verified.upn).toBe('alice@contoso.com')
    expect(verified.groups).toEqual(['group-admin-id'])

    // Wrong nonce must fail
    await expect(
      verifyEntraIdToken({
        idToken: validJwt,
        expectedNonce: 'wrong-nonce',
        tenantId: TENANT_ID,
        clientId: CLIENT_ID,
        jwks: publicKey,
      }),
    ).rejects.toThrow(/nonce/i)

    // Wrong tenant tid must fail (single-tenant enforcement)
    const crossTenantJwt = await new SignJWT({
      tid: '99999999-9999-9999-9999-999999999999',
      oid: 'user-oid-2',
      nonce: 'expected-nonce-xyz',
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(`https://login.microsoftonline.com/${TENANT_ID}/v2.0`)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)

    await expect(
      verifyEntraIdToken({
        idToken: crossTenantJwt,
        expectedNonce: 'expected-nonce-xyz',
        tenantId: TENANT_ID,
        clientId: CLIENT_ID,
        jwks: publicKey,
      }),
    ).rejects.toThrow(/tenant/i)
  })

  it('persists sessions in SQLite and sets Secure HttpOnly SameSite=Lax cookies behind HTTPS / NPM', () => {
    const { rawToken } = createSession({
      userOid: 'oid-1',
      userUpn: 'admin@contoso.com',
      displayName: 'Admin User',
      role: 'admin',
      groups: ['group-admin-id'],
    })

    const httpsCookie = buildSessionCookieHeader(rawToken)
    expect(httpsCookie).toContain('HttpOnly')
    expect(httpsCookie).toContain('SameSite=Lax')
    expect(httpsCookie).toContain('Secure')

    // Even if APP_BASE_URL is http, X-Forwarded-Proto: https must trigger Secure
    process.env.APP_BASE_URL = 'http://localhost:3000'
    resetConfigCache()
    const proxiedReq = new Request('http://pocket365:3000/api/auth/login', {
      headers: { 'x-forwarded-proto': 'https' },
    })
    const oidcCookie = buildOidcCookieHeader('binding-token', proxiedReq)
    expect(oidcCookie).toContain('Secure')
    expect(oidcCookie).toContain('HttpOnly')
    expect(oidcCookie).toContain('SameSite=Lax')

    const authedReq = new Request('http://pocket365:3000/users', {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${rawToken}` },
    })
    const loaded = getSessionFromRequest(authedReq)
    expect(loaded?.upn).toBe('admin@contoso.com')
    expect(loaded?.role).toBe('admin')

    destroySessionFromRequest(authedReq)
    expect(getSessionFromRequest(authedReq)).toBeNull()
  })

  it('strictly enforces requireRole("admin") returning 403 Forbidden for viewer and 401 for anonymous', async () => {
    const anonReq = new Request('https://pocket365.example.com/api/test')
    expect(() => requireRole('admin', anonReq)).toThrowError(AuthHttpError)
    const anonGuard = guardApiRole('admin', anonReq)
    expect(anonGuard.ok).toBe(false)
    if (!anonGuard.ok) {
      expect(anonGuard.response.status).toBe(401)
    }

    const { rawToken: viewerToken } = createSession({
      userOid: 'viewer-oid-123',
      userUpn: 'viewer@contoso.com',
      displayName: 'Read Only Viewer',
      role: 'viewer',
      groups: ['group-viewer-id'],
    })

    const viewerReq = new Request('https://pocket365.example.com/users', {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${viewerToken}` },
    })

    // Viewer can pass requireRole('viewer')
    expect(requireRole('viewer', viewerReq).role).toBe('viewer')

    // Viewer MUST receive 403 Forbidden on requireRole('admin')
    const guardRes = guardApiRole('admin', viewerReq, 'user.toggle_enabled')
    expect(guardRes.ok).toBe(false)
    if (!guardRes.ok) {
      expect(guardRes.response.status).toBe(403)
    }

    // RBAC denial should be recorded in audit logs
    const logs = listAuditLogs({ limit: 10 })
    expect(
      logs.some(
        (l) =>
          l.action === 'rbac.denied:user.toggle_enabled' &&
          l.actorUpn === 'viewer@contoso.com' &&
          l.status === 'failure',
      ),
    ).toBe(true)
  })
})
