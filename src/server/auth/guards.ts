import { getRequest, setResponseStatus } from '@tanstack/react-start/server'
import { recordAuditLog } from '~/server/db/audit'
import type { UserRole } from '~/server/db/schema'
import { getClientIp } from '~/server/http/proxy'
import { enforceRateLimit } from '~/server/security/rate-limit'
import { hasCapability, isAdminRole, type AppCapability } from './roles'
import { getSessionFromRequest, type SessionUser } from './session'

export class AuthHttpError extends Error {
  public readonly status: 401 | 403
  public readonly code: 'UNAUTHORIZED' | 'FORBIDDEN'

  constructor(status: 401 | 403, message: string) {
    super(message)
    this.name = 'AuthHttpError'
    this.status = status
    this.code = status === 401 ? 'UNAUTHORIZED' : 'FORBIDDEN'
  }
}

function safeGetCurrentRequest(explicitRequest?: Request): Request | undefined {
  if (explicitRequest) return explicitRequest
  try {
    return getRequest()
  } catch {
    return undefined
  }
}

function safeSetStatus(status: number): void {
  try {
    setResponseStatus(status)
  } catch {
    // Outside active TanStack Start server request context (e.g. direct unit tests)
  }
}

export function getCurrentSession(explicitRequest?: Request): SessionUser | null {
  const req = safeGetCurrentRequest(explicitRequest)
  return getSessionFromRequest(req)
}

/**
 * Ensures the caller holds a valid, unexpired server-side session.
 * Sets HTTP 401 and throws AuthHttpError when unauthenticated.
 */
export function requireSession(explicitRequest?: Request): SessionUser {
  const req = safeGetCurrentRequest(explicitRequest)
  const session = getSessionFromRequest(req)
  if (!session) {
    safeSetStatus(401)
    throw new AuthHttpError(401, 'Authentication required. Please sign in.')
  }
  return session
}

/**
 * Strictly enforces RBAC on the server for every protected/mutating server function
 * and API route handler. Returns 403 Forbidden when unauthorized.
 */
export function requireRole(
  requiredRole: UserRole,
  explicitRequest?: Request,
  actionContext?: string,
): SessionUser {
  const req = safeGetCurrentRequest(explicitRequest)
  const session = requireSession(req)

  const allowed =
    requiredRole === 'viewer'
      ? true
      : requiredRole === 'admin'
        ? isAdminRole(session.role)
        : requiredRole === 'owner'
          ? isAdminRole(session.role)
          : requiredRole === 'helpdesk'
            ? hasCapability(session.role, 'helpdesk.actions')
            : requiredRole === 'security_auditor'
              ? hasCapability(session.role, 'audit.sweep')
              : false

  if (!allowed) {
    safeSetStatus(403)
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: actionContext ? `rbac.denied:${actionContext}` : 'rbac.denied',
      target: req ? new URL(req.url).pathname : 'server_fn',
      status: 'failure',
      details: { requiredRole, actualRole: session.role },
      ipAddress: getClientIp(req),
    })
    throw new AuthHttpError(
      403,
      `Forbidden: ${requiredRole} privileges are required for this operation.`,
    )
  }

  if (requiredRole !== 'viewer') {
    enforceRateLimit('mutation', session.oid, req)
  }

  return session
}

/**
 * Capability-based server guard supporting granular RBAC roles
 * (owner, admin, helpdesk, security_auditor, viewer) + mutation rate limiting.
 */
export function requireCapability(
  capability: AppCapability,
  explicitRequest?: Request,
  actionContext?: string,
): SessionUser {
  const req = safeGetCurrentRequest(explicitRequest)
  const session = requireSession(req)

  if (!hasCapability(session.role, capability)) {
    safeSetStatus(403)
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: actionContext ? `rbac.denied:${actionContext}` : 'rbac.denied',
      target: req ? new URL(req.url).pathname : 'server_fn',
      status: 'failure',
      details: { requiredCapability: capability, actualRole: session.role },
      ipAddress: getClientIp(req),
    })
    throw new AuthHttpError(
      403,
      `Forbidden: missing required capability "${capability}" (current role: ${session.role}).`,
    )
  }

  if (capability !== 'read') {
    enforceRateLimit('mutation', session.oid, req)
  }

  return session
}

/**
 * Helper for raw HTTP API route handlers to return standard 401/403 JSON responses.
 */
export function guardApiRole(
  requiredRole: UserRole,
  request: Request,
  actionContext?: string,
):
  | { ok: true; session: SessionUser }
  | { ok: false; response: Response } {
  try {
    const session = requireRole(requiredRole, request, actionContext)
    return { ok: true, session }
  } catch (err) {
    if (err instanceof AuthHttpError) {
      return {
        ok: false,
        response: Response.json(
          { error: err.code, message: err.message },
          { status: err.status },
        ),
      }
    }
    throw err
  }
}
