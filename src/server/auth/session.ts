import crypto from 'node:crypto'
import { eq, lt } from 'drizzle-orm'
import { getConfig } from '~/server/config'
import { getDb } from '~/server/db'
import { sessions, type UserRole } from '~/server/db/schema'
import {
  isSecureRequest,
  parseCookies,
  serializeCookie,
} from '~/server/http/proxy'

export const SESSION_COOKIE_NAME = 'pocket365_session'
export const OIDC_COOKIE_NAME = 'pocket365_oidc'
const LAST_SEEN_UPDATE_INTERVAL_MS = 5 * 60 * 1000

export interface SessionUser {
  sessionId: string
  oid: string
  upn: string
  displayName: string
  role: UserRole
  groups: string[]
  expiresAt: number
}

export function hashSessionToken(rawToken: string): string {
  const cfg = getConfig()
  if (cfg.sessionSecret) {
    return crypto
      .createHmac('sha256', cfg.sessionSecret)
      .update(rawToken, 'utf8')
      .digest('hex')
  }
  return crypto.createHash('sha256').update(rawToken, 'utf8').digest('hex')
}

export function createSession(params: {
  userOid: string
  userUpn: string
  displayName: string
  role: UserRole
  groups: string[]
  ipAddress?: string | null
  userAgent?: string | null
}): { rawToken: string; session: SessionUser } {
  const cfg = getConfig()
  const db = getDb()
  const now = Date.now()
  const expiresAt = now + cfg.sessionTtlHours * 60 * 60 * 1000

  // Opportunistic cleanup of expired sessions
  db.delete(sessions).where(lt(sessions.expiresAt, now)).run()

  const rawToken = crypto.randomBytes(32).toString('base64url')
  const id = hashSessionToken(rawToken)

  db.insert(sessions)
    .values({
      id,
      userOid: params.userOid,
      userUpn: params.userUpn,
      displayName: params.displayName,
      role: params.role,
      groupsJson: JSON.stringify(params.groups),
      expiresAt,
      createdAt: now,
      lastSeenAt: now,
      ipAddress: params.ipAddress ?? null,
      userAgent: params.userAgent ?? null,
    })
    .run()

  return {
    rawToken,
    session: {
      sessionId: id,
      oid: params.userOid,
      upn: params.userUpn,
      displayName: params.displayName,
      role: params.role,
      groups: params.groups,
      expiresAt,
    },
  }
}

export function getSessionByRawToken(rawToken: string | undefined): SessionUser | null {
  if (!rawToken) return null
  const db = getDb()
  const id = hashSessionToken(rawToken)
  const row = db.select().from(sessions).where(eq(sessions.id, id)).get()
  if (!row) return null

  const now = Date.now()
  if (row.expiresAt <= now) {
    db.delete(sessions).where(eq(sessions.id, id)).run()
    return null
  }

  if (now - row.lastSeenAt > LAST_SEEN_UPDATE_INTERVAL_MS) {
    db.update(sessions)
      .set({ lastSeenAt: now })
      .where(eq(sessions.id, id))
      .run()
  }

  let groups: string[] = []
  try {
    const parsed = JSON.parse(row.groupsJson)
    if (Array.isArray(parsed)) {
      groups = parsed.filter((g): g is string => typeof g === 'string')
    }
  } catch {
    groups = []
  }

  return {
    sessionId: row.id,
    oid: row.userOid,
    upn: row.userUpn,
    displayName: row.displayName,
    role: row.role,
    groups,
    expiresAt: row.expiresAt,
  }
}

export function getSessionFromRequest(request?: Request): SessionUser | null {
  if (!request) return null
  const cookies = parseCookies(request.headers.get('cookie'))
  return getSessionByRawToken(cookies[SESSION_COOKIE_NAME])
}

export function destroySessionFromRequest(request?: Request): SessionUser | null {
  if (!request) return null
  const cookies = parseCookies(request.headers.get('cookie'))
  const rawToken = cookies[SESSION_COOKIE_NAME]
  if (!rawToken) return null

  const session = getSessionByRawToken(rawToken)
  const id = hashSessionToken(rawToken)
  const db = getDb()
  db.delete(sessions).where(eq(sessions.id, id)).run()
  return session
}

export function buildSessionCookieHeader(
  rawToken: string,
  request?: Request,
): string {
  const cfg = getConfig()
  return serializeCookie(SESSION_COOKIE_NAME, rawToken, {
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
    path: '/',
    maxAge: cfg.sessionTtlHours * 60 * 60,
  })
}

export function buildClearSessionCookieHeader(request?: Request): string {
  return serializeCookie(SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
    path: '/',
    maxAge: 0,
    expires: new Date(0),
  })
}

export function buildOidcCookieHeader(
  bindingToken: string,
  request?: Request,
): string {
  return serializeCookie(OIDC_COOKIE_NAME, bindingToken, {
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
    path: '/api/auth/callback',
    maxAge: 600,
  })
}

export function buildClearOidcCookieHeader(request?: Request): string {
  return serializeCookie(OIDC_COOKIE_NAME, '', {
    httpOnly: true,
    secure: isSecureRequest(request),
    sameSite: 'Lax',
    path: '/api/auth/callback',
    maxAge: 0,
    expires: new Date(0),
  })
}
