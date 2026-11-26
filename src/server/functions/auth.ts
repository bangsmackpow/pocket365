import { createServerFn } from '@tanstack/react-start'
import { getCurrentSession } from '~/server/auth/guards'
import { getConfig, getConfigReadiness } from '~/server/config'
import { getEffectiveEntraConfig } from '~/server/setup/service'
import {
  listAccessibleTenants,
  resolveActiveTenantForSession,
} from '~/server/tenants/registry'

export const getSessionFn = createServerFn({ method: 'GET' }).handler(async () => {
  const session = await getCurrentSession()
  const cfg = getConfig()
  const baseReadiness = getConfigReadiness()
  const effective = await getEffectiveEntraConfig()

  const hasCertAuth = Boolean(
    effective.graphClientId &&
      effective.graphCertThumbprint &&
      effective.graphCertPrivateKey,
  )
  const hasSecretAuth = Boolean(
    effective.graphClientId && effective.graphClientSecret,
  )

  const readiness = {
    ...baseReadiness,
    singleTenantConfigured:
      baseReadiness.singleTenantConfigured || Boolean(effective.entraTenantId),
    oidcConfigured:
      baseReadiness.oidcConfigured ||
      Boolean(
        effective.entraTenantId &&
          effective.oidcClientId &&
          effective.oidcClientSecret,
      ),
    graphConfigured:
      baseReadiness.graphConfigured ||
      Boolean(effective.entraTenantId && (hasCertAuth || hasSecretAuth)),
    graphAuthMode: hasCertAuth
      ? ('certificate' as const)
      : hasSecretAuth
        ? ('client_secret' as const)
        : baseReadiness.graphAuthMode,
    rbacConfigured:
      baseReadiness.rbacConfigured ||
      effective.ownerEntries.length > 0 ||
      effective.adminEntries.length > 0,
  }

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
