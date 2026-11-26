import { createServerFn } from '@tanstack/react-start'
import { getCurrentSession } from '~/server/auth/guards'
import { getConfig } from '~/server/config'
import {
  getEffectiveConfigReadiness,
  getEffectiveEntraConfig,
} from '~/server/setup/service'
import {
  listAccessibleTenants,
  resolveActiveTenantForSession,
} from '~/server/tenants/registry'

export const getSessionFn = createServerFn({ method: 'GET' }).handler(async () => {
  const session = await getCurrentSession()
  const cfg = getConfig()
  const [readiness, effective] = await Promise.all([
    getEffectiveConfigReadiness(),
    getEffectiveEntraConfig(),
  ])

  const accessibleTenants = session
    ? (await listAccessibleTenants(session)).map((t) => ({
        id: t.id,
        displayName: t.displayName,
        primaryDomain: t.primaryDomain,
        isPrimary: t.isPrimary === 1,
      }))
    : []

  const activeTenant = session
    ? await resolveActiveTenantForSession(session)
    : null

  const needsSetup =
    cfg.deploymentMode === 'self_hosted' && !readiness.oidcConfigured

  return {
    deploymentMode: cfg.deploymentMode,
    needsSetup,
    user: session
      ? {
          oid: session.oid,
          upn: session.upn,
          displayName: session.displayName,
          role: session.role,
          expiresAt: session.expiresAt,
          organizationId: session.organizationId,
        }
      : null,
    activeTenantId: activeTenant?.id ?? null,
    accessibleTenants: cfg.deploymentMode === 'saas' ? accessibleTenants : [],
    tenantIdHint: activeTenant
      ? `${activeTenant.entraTenantId.slice(0, 8)}...`
      : effective.entraTenantId
        ? `${effective.entraTenantId.slice(0, 8)}...`
        : null,
    readiness,
  }
})
