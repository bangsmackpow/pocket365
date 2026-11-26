import crypto from 'node:crypto'
import { asc, eq, inArray } from 'drizzle-orm'
import { isAdminRole } from '~/server/auth/roles'
import type { SessionUser } from '~/server/auth/session'
import { getConfig } from '~/server/config'
import { getDb } from '~/server/db'
import {
  managedTenants,
  oidcStates,
  sessions,
  tenantAccess,
  type ManagedTenantRow,
  type TenantConnectionMode,
} from '~/server/db/schema'
import type { TenantGraphCredentials } from '~/server/graph/auth'
import { buildCanonicalUrl } from '~/server/http/proxy'
import { decryptSecret, encryptSecret } from '~/server/security/crypto'

/**
 * Ensures the primary tenant configured via ENTRA_TENANT_ID is seeded into
 * `managed_tenants` so existing single-tenant deployments upgrade seamlessly.
 */
export function ensurePrimaryTenantSeeded(): ManagedTenantRow | null {
  const cfg = getConfig()
  if (!cfg.entraTenantId) return null

  const db = getDb()
  const existing = db
    .select()
    .from(managedTenants)
    .where(eq(managedTenants.entraTenantId, cfg.entraTenantId))
    .get()

  if (existing) {
    return existing
  }

  const now = Date.now()
  const row: ManagedTenantRow = {
    id: crypto.randomUUID(),
    entraTenantId: cfg.entraTenantId,
    displayName: 'Primary Tenant',
    primaryDomain: '',
    connectionMode: 'env_primary',
    clientId: cfg.graphClientId || '',
    clientSecretEnc: null,
    certThumbprint: null,
    certPrivateKeyEnc: null,
    isPrimary: 1,
    status: 'active',
    lastHealthCheckAt: null,
    lastHealthError: null,
    lastCisScorePct: null,
    lastMfaCoveragePct: null,
    createdBy: 'system:env',
    createdAt: now,
    updatedAt: now,
  }

  db.insert(managedTenants).values(row).run()
  return row
}

export function listAllManagedTenants(): ManagedTenantRow[] {
  ensurePrimaryTenantSeeded()
  const db = getDb()
  return db
    .select()
    .from(managedTenants)
    .orderBy(asc(managedTenants.createdAt))
    .all()
}

export function getManagedTenantById(id: string): ManagedTenantRow | null {
  ensurePrimaryTenantSeeded()
  const db = getDb()
  return (
    db.select().from(managedTenants).where(eq(managedTenants.id, id)).get() ??
    null
  )
}

/**
 * Returns managed tenants accessible to the signed-in user.
 * Owners/Admins can access all managed tenants. Other roles are scoped to
 * `tenant_access` if any explicit grants exist for them, otherwise primary tenant.
 */
export function listAccessibleTenants(session: SessionUser): ManagedTenantRow[] {
  const all = listAllManagedTenants()
  if (isAdminRole(session.role)) {
    return all
  }

  const db = getDb()
  const principals = [session.upn.toLowerCase(), session.oid.toLowerCase()]
  const grants = db
    .select()
    .from(tenantAccess)
    .where(inArray(tenantAccess.principal, principals))
    .all()

  if (grants.length === 0) {
    return all.filter((t) => t.isPrimary === 1)
  }

  const allowedIds = new Set(grants.map((g) => g.managedTenantId))
  return all.filter((t) => allowedIds.has(t.id))
}

export function canAccessTenant(
  session: SessionUser,
  managedTenantId: string,
): boolean {
  const accessible = listAccessibleTenants(session)
  return accessible.some((t) => t.id === managedTenantId)
}

export function resolveActiveTenantForSession(
  session: SessionUser | null,
): ManagedTenantRow | null {
  ensurePrimaryTenantSeeded()
  if (!session) {
    const all = listAllManagedTenants()
    return all.find((t) => t.isPrimary === 1) ?? all[0] ?? null
  }

  const accessible = listAccessibleTenants(session)
  if (session.activeTenantId) {
    const match = accessible.find((t) => t.id === session.activeTenantId)
    if (match) return match
  }
  return accessible.find((t) => t.isPrimary === 1) ?? accessible[0] ?? null
}

export function setSessionActiveTenant(
  session: SessionUser,
  managedTenantId: string,
): ManagedTenantRow {
  const target = getManagedTenantById(managedTenantId)
  if (!target) {
    throw new Error('Managed tenant not found.')
  }
  if (!canAccessTenant(session, target.id)) {
    throw new Error('Forbidden: you do not have access to this managed tenant.')
  }

  const db = getDb()
  db.update(sessions)
    .set({ activeTenantId: target.id })
    .where(eq(sessions.id, session.sessionId))
    .run()

  return target
}

/**
 * Resolves isolated Microsoft Graph app-only credentials for a specific managed tenant.
 * Never leaks secrets across tenant boundaries.
 */
export function resolveTenantGraphCredentials(
  tenant: ManagedTenantRow,
): TenantGraphCredentials {
  const cfg = getConfig()

  if (tenant.connectionMode === 'env_primary') {
    return {
      entraTenantId: tenant.entraTenantId,
      clientId: cfg.graphClientId,
      clientSecret: cfg.graphClientSecret || undefined,
      certThumbprint: cfg.graphCertThumbprint || undefined,
      certPrivateKey: cfg.graphCertPrivateKey || undefined,
    }
  }

  if (tenant.connectionMode === 'admin_consent') {
    // Uses Pocket365's multi-tenant Graph app credentials against the customer's tenant ID
    return {
      entraTenantId: tenant.entraTenantId,
      clientId: tenant.clientId || cfg.graphClientId,
      clientSecret: cfg.graphClientSecret || undefined,
      certThumbprint: cfg.graphCertThumbprint || undefined,
      certPrivateKey: cfg.graphCertPrivateKey || undefined,
    }
  }

  // Dedicated per-tenant app credentials encrypted at rest in SQLite
  return {
    entraTenantId: tenant.entraTenantId,
    clientId: tenant.clientId,
    clientSecret: tenant.clientSecretEnc
      ? decryptSecret(tenant.clientSecretEnc)
      : undefined,
    certThumbprint: tenant.certThumbprint || undefined,
    certPrivateKey: tenant.certPrivateKeyEnc
      ? decryptSecret(tenant.certPrivateKeyEnc)
      : undefined,
  }
}

export function createManagedTenantRecord(params: {
  entraTenantId: string
  displayName: string
  primaryDomain?: string
  connectionMode: Exclude<TenantConnectionMode, 'env_primary'>
  clientId?: string
  clientSecret?: string
  certThumbprint?: string
  certPrivateKey?: string
  createdBy: string
}): ManagedTenantRow {
  const db = getDb()
  const now = Date.now()
  const id = crypto.randomUUID()
  const row: ManagedTenantRow = {
    id,
    entraTenantId: params.entraTenantId.trim(),
    displayName: params.displayName.trim(),
    primaryDomain: (params.primaryDomain || '').trim(),
    connectionMode: params.connectionMode,
    clientId: (params.clientId || '').trim(),
    clientSecretEnc: params.clientSecret
      ? encryptSecret(params.clientSecret.trim())
      : null,
    certThumbprint: params.certThumbprint?.trim() || null,
    certPrivateKeyEnc: params.certPrivateKey
      ? encryptSecret(params.certPrivateKey.trim())
      : null,
    isPrimary: 0,
    status: 'active',
    lastHealthCheckAt: null,
    lastHealthError: null,
    lastCisScorePct: null,
    lastMfaCoveragePct: null,
    createdBy: params.createdBy,
    createdAt: now,
    updatedAt: now,
  }

  db.insert(managedTenants).values(row).run()
  return row
}

export function createAdminConsentRequestUrl(
  actorUpn: string,
  request?: Request,
): { consentUrl: string; state: string } {
  const cfg = getConfig()
  if (!cfg.graphClientId) {
    throw new Error('GRAPH_CLIENT_ID must be configured for Admin Consent onboarding.')
  }

  const db = getDb()
  const state = `consent_${crypto.randomBytes(24).toString('base64url')}`
  const now = Date.now()
  db.insert(oidcStates)
    .values({
      state,
      nonce: actorUpn,
      codeVerifier: 'admin_consent',
      cookieBindingHash: 'admin_consent',
      returnTo: '/tenants',
      expiresAt: now + 60 * 60 * 1000, // 1 hour for customer admin to click link
      createdAt: now,
    })
    .run()

  const redirectUri = buildCanonicalUrl('/api/tenants/consent-callback', request)
  const params = new URLSearchParams({
    client_id: cfg.graphClientId,
    state,
    redirect_uri: redirectUri,
  })

  return {
    consentUrl: `https://login.microsoftonline.com/organizations/adminconsent?${params.toString()}`,
    state,
  }
}
