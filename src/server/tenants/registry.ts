import crypto from 'node:crypto'
import { and, asc, eq, inArray } from 'drizzle-orm'
import { isAdminRole } from '~/server/auth/roles'
import { evictSessionCache, type SessionUser } from '~/server/auth/session'
import { getConfig } from '~/server/config'
import { getDb } from '~/server/db'
import {
  managedTenants,
  oidcStates,
  organizations,
  sessions,
  tenantAccess,
  type ManagedTenantRow,
  type TenantConnectionMode,
} from '~/server/db/schema'
import type { TenantGraphCredentials } from '~/server/graph/auth'
import { buildCanonicalUrl } from '~/server/http/proxy'
import { DEFAULT_ORG_ID } from '~/server/orgs/service'
import { decryptSecret, encryptSecret } from '~/server/security/crypto'
import { getEffectiveEntraConfig } from '~/server/setup/service'

/**
 * In `self_hosted` mode, ensures the primary tenant configured via ENTRA_TENANT_ID
 * or the `/setup` wizard is seeded into `managed_tenants` under the default organization.
 * In `saas` mode, organizations connect their own M365 tenants via Admin Consent.
 */
export async function ensurePrimaryTenantSeeded(
  organizationId = DEFAULT_ORG_ID,
): Promise<ManagedTenantRow | null> {
  const cfg = getConfig()
  const db = getDb()

  if (organizationId !== DEFAULT_ORG_ID) {
    const org = await db
      .select()
      .from(organizations)
      .where(eq(organizations.id, organizationId))
      .get()
    if (!org || !org.homeEntraTenantId) return null

    const anyExisting = await db
      .select()
      .from(managedTenants)
      .where(eq(managedTenants.organizationId, organizationId))
      .all()

    if (anyExisting.length > 0) {
      return (
        anyExisting.find((t) => t.isPrimary === 1) ||
        anyExisting.find((t) => t.entraTenantId === org.homeEntraTenantId) ||
        anyExisting[0] ||
        null
      )
    }

    const domainPart = org.ownerUpn.includes('@')
      ? org.ownerUpn.split('@')[1]
      : ''
    const now = Date.now()
    const row: ManagedTenantRow = {
      id: crypto.randomUUID(),
      organizationId,
      entraTenantId: org.homeEntraTenantId,
      displayName: org.name || (domainPart ? domainPart : `Tenant ${org.homeEntraTenantId.slice(0, 8)}`),
      primaryDomain: domainPart || '',
      connectionMode: 'admin_consent',
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
      createdBy: org.ownerUpn || 'system:auto_org',
      createdAt: now,
      updatedAt: now,
    }
    await db.insert(managedTenants).values(row).run()
    return row
  }

  const effective = await getEffectiveEntraConfig()
  const primaryTenantId = cfg.entraTenantId || effective.entraTenantId
  if (!primaryTenantId) return null

  const existing = await db
    .select()
    .from(managedTenants)
    .where(
      and(
        eq(managedTenants.organizationId, DEFAULT_ORG_ID),
        eq(managedTenants.entraTenantId, primaryTenantId),
      ),
    )
    .get()

  if (existing) {
    return existing
  }

  const now = Date.now()
  const row: ManagedTenantRow = {
    id: crypto.randomUUID(),
    organizationId: DEFAULT_ORG_ID,
    entraTenantId: primaryTenantId,
    displayName: 'Primary Tenant',
    primaryDomain: '',
    connectionMode: 'env_primary',
    clientId: cfg.graphClientId || effective.graphClientId || '',
    clientSecretEnc: null,
    certThumbprint: null,
    certPrivateKeyEnc: null,
    isPrimary: 1,
    status: 'active',
    lastHealthCheckAt: null,
    lastHealthError: null,
    lastCisScorePct: null,
    lastMfaCoveragePct: null,
    createdBy: effective.source === 'd1_setup' ? 'system:setup' : 'system:env',
    createdAt: now,
    updatedAt: now,
  }

  await db.insert(managedTenants).values(row).run()
  return row
}

export async function listAllManagedTenants(
  organizationId = DEFAULT_ORG_ID,
): Promise<ManagedTenantRow[]> {
  await ensurePrimaryTenantSeeded(organizationId)
  const db = getDb()
  return db
    .select()
    .from(managedTenants)
    .where(eq(managedTenants.organizationId, organizationId))
    .orderBy(asc(managedTenants.createdAt))
    .all()
}

export async function getManagedTenantById(
  id: string,
  organizationId?: string,
): Promise<ManagedTenantRow | null> {
  await ensurePrimaryTenantSeeded(organizationId ?? DEFAULT_ORG_ID)
  const db = getDb()
  const whereClause = organizationId
    ? and(
        eq(managedTenants.id, id),
        eq(managedTenants.organizationId, organizationId),
      )
    : eq(managedTenants.id, id)

  return (
    (await db.select().from(managedTenants).where(whereClause).get()) ?? null
  )
}

/**
 * Returns managed tenants accessible to the signed-in user strictly within
 * their own `organizationId`.
 */
export async function listAccessibleTenants(
  session: SessionUser,
): Promise<ManagedTenantRow[]> {
  const orgId = session.organizationId || DEFAULT_ORG_ID
  const all = await listAllManagedTenants(orgId)
  if (isAdminRole(session.role)) {
    return all
  }

  const db = getDb()
  const principals = [session.upn.toLowerCase(), session.oid.toLowerCase()]
  const grants = await db
    .select()
    .from(tenantAccess)
    .where(
      and(
        eq(tenantAccess.organizationId, orgId),
        inArray(tenantAccess.principal, principals),
      ),
    )
    .all()

  if (grants.length === 0) {
    return all.filter((t) => t.isPrimary === 1)
  }

  const allowedIds = new Set(grants.map((g) => g.managedTenantId))
  return all.filter((t) => allowedIds.has(t.id))
}

export async function canAccessTenant(
  session: SessionUser,
  managedTenantId: string,
): Promise<boolean> {
  const accessible = await listAccessibleTenants(session)
  return accessible.some((t) => t.id === managedTenantId)
}

export async function resolveActiveTenantForSession(
  session: SessionUser | null,
): Promise<ManagedTenantRow | null> {
  const orgId = session?.organizationId || DEFAULT_ORG_ID
  await ensurePrimaryTenantSeeded(orgId)
  if (!session) {
    const all = await listAllManagedTenants(DEFAULT_ORG_ID)
    return all.find((t) => t.isPrimary === 1) ?? all[0] ?? null
  }

  const accessible = await listAccessibleTenants(session)
  if (session.activeTenantId) {
    const match = accessible.find((t) => t.id === session.activeTenantId)
    if (match) return match
  }
  return accessible.find((t) => t.isPrimary === 1) ?? accessible[0] ?? null
}

export async function setSessionActiveTenant(
  session: SessionUser,
  managedTenantId: string,
): Promise<ManagedTenantRow> {
  const orgId = session.organizationId || DEFAULT_ORG_ID
  const target = await getManagedTenantById(managedTenantId, orgId)
  if (!target) {
    throw new Error('Managed tenant not found.')
  }
  if (!(await canAccessTenant(session, target.id))) {
    throw new Error('Forbidden: you do not have access to this managed tenant.')
  }

  const db = getDb()
  await db
    .update(sessions)
    .set({ activeTenantId: target.id })
    .where(
      and(
        eq(sessions.id, session.sessionId),
        eq(sessions.organizationId, orgId),
      ),
    )
    .run()

  evictSessionCache(session.sessionId)

  return target
}

/**
 * Resolves isolated Microsoft Graph app-only credentials for a specific managed tenant.
 * Never leaks secrets across tenant or organization boundaries.
 */
export function resolveTenantGraphCredentials(
  tenant: ManagedTenantRow,
): TenantGraphCredentials {
  const cfg = getConfig()
  const organizationId = tenant.organizationId || DEFAULT_ORG_ID

  if (tenant.connectionMode === 'env_primary') {
    return {
      organizationId,
      entraTenantId: tenant.entraTenantId,
      clientId: cfg.graphClientId,
      clientSecret: cfg.graphClientSecret || undefined,
      certThumbprint: cfg.graphCertThumbprint || undefined,
      certPrivateKey: cfg.graphCertPrivateKey || undefined,
    }
  }

  if (tenant.connectionMode === 'admin_consent') {
    // Zero per-customer secrets: uses Pocket365's multi-tenant Graph app cert/secret
    return {
      organizationId,
      entraTenantId: tenant.entraTenantId,
      clientId: tenant.clientId || cfg.graphClientId,
      clientSecret: cfg.graphClientSecret || cfg.oidcClientSecret || undefined,
      certThumbprint: cfg.graphCertThumbprint || undefined,
      certPrivateKey: cfg.graphCertPrivateKey || undefined,
    }
  }

  // Dedicated per-tenant app credentials encrypted at rest in D1
  return {
    organizationId,
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

export async function createManagedTenantRecord(params: {
  organizationId?: string
  entraTenantId: string
  displayName: string
  primaryDomain?: string
  connectionMode: Exclude<TenantConnectionMode, 'env_primary'>
  clientId?: string
  clientSecret?: string
  certThumbprint?: string
  certPrivateKey?: string
  isPrimary?: boolean
  createdBy: string
}): Promise<ManagedTenantRow> {
  const db = getDb()
  const now = Date.now()
  const id = crypto.randomUUID()
  const row: ManagedTenantRow = {
    id,
    organizationId: params.organizationId?.trim() || DEFAULT_ORG_ID,
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
    isPrimary: params.isPrimary ? 1 : 0,
    status: 'active',
    lastHealthCheckAt: null,
    lastHealthError: null,
    lastCisScorePct: null,
    lastMfaCoveragePct: null,
    createdBy: params.createdBy,
    createdAt: now,
    updatedAt: now,
  }

  await db.insert(managedTenants).values(row).run()
  return row
}

export async function createAdminConsentRequestUrl(
  actorUpn: string,
  request?: Request,
  organizationId = DEFAULT_ORG_ID,
): Promise<{ consentUrl: string; state: string }> {
  const cfg = getConfig()
  if (!cfg.graphClientId) {
    throw new Error(
      'GRAPH_CLIENT_ID must be configured for Admin Consent onboarding.',
    )
  }

  const db = getDb()
  const state = `consent_${crypto.randomBytes(24).toString('base64url')}`
  const now = Date.now()
  await db
    .insert(oidcStates)
    .values({
      state,
      nonce: `${organizationId}|${actorUpn}`,
      codeVerifier: 'admin_consent',
      cookieBindingHash: organizationId,
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
