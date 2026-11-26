import crypto from 'node:crypto'
import { and, desc, eq, lt, ne } from 'drizzle-orm'
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
  activeTenantId: string | null
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

export async function createSession(params: {
  userOid: string
  userUpn: string
  displayName: string
  role: UserRole
  groups: string[]
  ipAddress?: string | null
  userAgent?: string | null
}): Promise<{ rawToken: string; session: SessionUser }> {
  const cfg = getConfig()
  const db = getDb()
  const now = Date.now()
  const expiresAt = now + cfg.sessionTtlHours * 60 * 60 * 1000

  // Opportunistic cleanup of expired sessions
  await db.delete(sessions).where(lt(sessions.expiresAt, now)).run()

  const rawToken = crypto.randomBytes(32).toString('base64url')
  const id = hashSessionToken(rawToken)

  await db
    .insert(sessions)
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
      activeTenantId: null,
    },
  }
}

export async function getSessionByRawToken(
  rawToken: string | undefined,
): Promise<SessionUser | null> {
  if (!rawToken) return null
  const db = getDb()
  const id = hashSessionToken(rawToken)
  const row = await db.select().from(sessions).where(eq(sessions.id, id)).get()
  if (!row) return null

  const now = Date.now()
  const cfg = getConfig()
  const idleLimitMs = cfg.sessionIdleTimeoutMinutes * 60 * 1000
  if (row.expiresAt <= now || now - row.lastSeenAt > idleLimitMs) {
    await db.delete(sessions).where(eq(sessions.id, id)).run()
    return null
  }

  if (now - row.lastSeenAt > LAST_SEEN_UPDATE_INTERVAL_MS) {
    await db
      .update(sessions)
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
    activeTenantId: row.activeTenantId ?? null,
  }
}

export async function getSessionFromRequest(
  request?: Request,
): Promise<SessionUser | null> {
  if (!request) return null
  const cookies = parseCookies(request.headers.get('cookie'))
  return getSessionByRawToken(cookies[SESSION_COOKIE_NAME])
}

export async function destroySessionFromRequest(
  request?: Request,
): Promise<SessionUser | null> {
  if (!request) return null
  const cookies = parseCookies(request.headers.get('cookie'))
  const rawToken = cookies[SESSION_COOKIE_NAME]
  if (!rawToken) return null

  const session = await getSessionByRawToken(rawToken)
  const id = hashSessionToken(rawToken)
  const db = getDb()
  await db.delete(sessions).where(eq(sessions.id, id)).run()
  return session
}

export async function listActiveSessions(onlyUserOid?: string) {
  const db = getDb()
  const now = Date.now()
  await db.delete(sessions).where(lt(sessions.expiresAt, now)).run()

  return db
    .select({
      id: sessions.id,
      userOid: sessions.userOid,
      userUpn: sessions.userUpn,
      displayName: sessions.displayName,
      role: sessions.role,
      ipAddress: sessions.ipAddress,
      userAgent: sessions.userAgent,
      createdAt: sessions.createdAt,
      lastSeenAt: sessions.lastSeenAt,
      expiresAt: sessions.expiresAt,
    })
    .from(sessions)
    .where(onlyUserOid ? eq(sessions.userOid, onlyUserOid) : undefined)
    .orderBy(desc(sessions.lastSeenAt))
    .limit(100)
    .all()
}

export async function revokeSessionById(sessionId: string): Promise<void> {
  const db = getDb()
  await db.delete(sessions).where(eq(sessions.id, sessionId)).run()
}

export async function revokeOtherUserSessions(
  userOid: string,
  keepSessionId: string,
): Promise<number> {
  const db = getDb()
  const res = await db
    .delete(sessions)
    .where(and(eq(sessions.userOid, userOid), ne(sessions.id, keepSessionId)))
    .run()
  return res.meta?.changes ?? 0
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
