import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { isAdminRole } from '~/server/auth/roles'
import {
  listActiveSessions,
  revokeOtherUserSessions,
  revokeSessionById,
} from '~/server/auth/session'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { getClientIp } from '~/server/http/proxy'

export const getSecurityCenterDataFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    const session = requireSession()
    const cfg = getConfig()
    const isAdmin = isAdminRole(session.role)
    const activeSessions = listActiveSessions(isAdmin ? undefined : session.oid)

    return {
      currentSessionId: session.sessionId,
      sessions: activeSessions.map((s) => ({
        ...s,
        isCurrent: s.id === session.sessionId,
      })),
      controls: {
        rateLimiting: true,
        csrfOriginCheck: true,
        securityHeaders: true,
        webhookEncryption: true,
        explicitEncryptionKey: Boolean(cfg.dataEncryptionKey),
        ssrfProtection: !cfg.allowPrivateWebhooks,
        sessionIdleTimeoutMinutes: cfg.sessionIdleTimeoutMinutes,
        sessionAbsoluteTtlHours: cfg.sessionTtlHours,
        trustedProxyHops: cfg.trustedProxyHops,
      },
    }
  },
)

const revokeSessionSchema = z.object({
  sessionId: z.string().min(10),
})

export const revokeSessionFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => revokeSessionSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'session.revoke')
    revokeSessionById(data.sessionId)
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'session.revoke',
      target: data.sessionId.slice(0, 12),
      status: 'success',
      details: {},
      ipAddress: getClientIp(getRequest()),
    })
    return { ok: true }
  })

export const revokeMyOtherSessionsFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const session = requireSession()
    const count = revokeOtherUserSessions(session.oid, session.sessionId)
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'session.revoke_others',
      target: session.upn,
      status: 'success',
      details: { revokedCount: count },
      ipAddress: getClientIp(getRequest()),
    })
    return { ok: true, revokedCount: count }
  },
)
