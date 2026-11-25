import { createServerFn } from '@tanstack/react-start'
import { getCurrentSession } from '~/server/auth/guards'
import { getConfig, getConfigReadiness } from '~/server/config'

export const getSessionFn = createServerFn({ method: 'GET' }).handler(async () => {
  const session = getCurrentSession()
  const readiness = getConfigReadiness()
  const cfg = getConfig()

  return {
    user: session
      ? {
          oid: session.oid,
          upn: session.upn,
          displayName: session.displayName,
          role: session.role,
          expiresAt: session.expiresAt,
        }
      : null,
    tenantIdHint: cfg.entraTenantId
      ? `${cfg.entraTenantId.slice(0, 8)}...`
      : null,
    readiness,
  }
})
