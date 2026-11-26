import { createServerFn } from '@tanstack/react-start'
import { getCurrentSession } from '~/server/auth/guards'
import { getConfig, getConfigReadiness } from '~/server/config'
import {
  listAccessibleTenants,
  resolveActiveTenantForSession,
} from '~/server/tenants/registry'

export const getSessionFn = createServerFn({ method: 'GET' }).handler(async () => {
  const session = getCurrentSession()
  const readiness = getConfigReadiness()
  const cfg = getConfig()

  const accessibleTenants = session
    ? listAccessibleTenants(session).map((t) => ({
        id: t.id,
        displayName: t.displayName,
        primaryDomain: t.primaryDomain,
        isPrimary: t.isPrimary === 1,
      }))
    : []

  const activeTenant = session ? resolveActiveTenantForSession(session) : null

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
    activeTenantId: activeTenant?.id ?? null,
    accessibleTenants,
    tenantIdHint: activeTenant
      ? `${activeTenant.entraTenantId.slice(0, 8)}...`
      : cfg.entraTenantId
        ? `${cfg.entraTenantId.slice(0, 8)}...`
        : null,
    readiness,
  }
})
