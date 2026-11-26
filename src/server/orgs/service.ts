import crypto from 'node:crypto'
import { eq } from 'drizzle-orm'
import { getDb } from '~/server/db'
import {
  organizations,
  type OrganizationRow,
  type PlanTier,
  type SubscriptionStatus,
} from '~/server/db/schema'

export const DEFAULT_ORG_ID = 'default'

export function resolveOrgId(
  sessionOrOrgId?: { organizationId?: string } | string | null,
): string {
  if (!sessionOrOrgId) return DEFAULT_ORG_ID
  if (typeof sessionOrOrgId === 'string') {
    return sessionOrOrgId.trim() || DEFAULT_ORG_ID
  }
  return sessionOrOrgId.organizationId?.trim() || DEFAULT_ORG_ID
}

export async function ensureDefaultOrganization(): Promise<OrganizationRow> {
  const db = getDb()
  const existing = await db
    .select()
    .from(organizations)
    .where(eq(organizations.id, DEFAULT_ORG_ID))
    .get()
  if (existing) return existing

  const now = Date.now()
  const row: OrganizationRow = {
    id: DEFAULT_ORG_ID,
    name: 'Default Organization',
    slug: 'default',
    homeEntraTenantId: null,
    ownerUpn: 'system',
    planTier: 'community',
    stripeCustomerId: null,
    stripeSubscriptionId: null,
    subscriptionStatus: 'inactive',
    createdAt: now,
    updatedAt: now,
  }
  await db.insert(organizations).values(row).run()
  return row
}

export async function getOrganizationById(
  id: string,
): Promise<OrganizationRow | null> {
  const db = getDb()
  return (
    (await db
      .select()
      .from(organizations)
      .where(eq(organizations.id, id))
      .get()) ?? null
  )
}

export async function findOrganizationByStripeCustomerId(
  stripeCustomerId: string,
): Promise<OrganizationRow | null> {
  if (!stripeCustomerId) return null
  const db = getDb()
  return (
    (await db
      .select()
      .from(organizations)
      .where(eq(organizations.stripeCustomerId, stripeCustomerId))
      .get()) ?? null
  )
}

/**
 * In SaaS mode (`DEPLOYMENT_MODE=saas`), maps a Microsoft Entra home tenant ID (`tid`)
 * to its isolated Pocket365 Organization, auto-provisioning on first Microsoft admin sign-in.
 */
export async function findOrCreateOrgForEntraTenant(params: {
  homeEntraTenantId: string
  ownerUpn: string
  displayName?: string
}): Promise<{ org: OrganizationRow; created: boolean }> {
  const db = getDb()
  const normalizedTid = params.homeEntraTenantId.trim().toLowerCase()
  const existing = await db
    .select()
    .from(organizations)
    .where(eq(organizations.homeEntraTenantId, normalizedTid))
    .get()

  if (existing) {
    return { org: existing, created: false }
  }

  const now = Date.now()
  const id = `org_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`
  const domainPart = params.ownerUpn.includes('@')
    ? params.ownerUpn.split('@')[1] || ''
    : ''
  const name =
    params.displayName?.trim() ||
    (domainPart ? `${domainPart} Organization` : `Tenant ${normalizedTid.slice(0, 8)}`)
  const slugBase = (domainPart || normalizedTid.slice(0, 12))
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
  const slug = `${slugBase || 'org'}-${id.slice(-6)}`

  const row: OrganizationRow = {
    id,
    name,
    slug,
    homeEntraTenantId: normalizedTid,
    ownerUpn: params.ownerUpn.toLowerCase(),
    planTier: 'community',
    stripeCustomerId: null,
    stripeSubscriptionId: null,
    subscriptionStatus: 'inactive',
    createdAt: now,
    updatedAt: now,
  }

  await db.insert(organizations).values(row).run()
  return { org: row, created: true }
}

export async function updateOrganizationBilling(params: {
  organizationId: string
  planTier: PlanTier
  stripeCustomerId?: string | null
  stripeSubscriptionId?: string | null
  subscriptionStatus: SubscriptionStatus
}): Promise<void> {
  const db = getDb()
  await db
    .update(organizations)
    .set({
      planTier: params.planTier,
      stripeCustomerId: params.stripeCustomerId ?? undefined,
      stripeSubscriptionId: params.stripeSubscriptionId ?? undefined,
      subscriptionStatus: params.subscriptionStatus,
      updatedAt: Date.now(),
    })
    .where(eq(organizations.id, params.organizationId))
    .run()
}

/**
 * Generates an organization-scoped R2 export key so orgs cannot access each other's artifacts.
 */
export function buildOrgExportKey(
  organizationId: string,
  category: string,
  filename: string,
): string {
  const safeOrg = organizationId.replace(/[^a-zA-Z0-9_-]/g, '')
  const safeCat = category.replace(/[^a-zA-Z0-9_-]/g, '')
  const safeFile = filename.replace(/[^a-zA-Z0-9._-]/g, '_')
  return `exports/orgs/${safeOrg || DEFAULT_ORG_ID}/${safeCat}/${safeFile}`
}

export function isExportKeyOwnedByOrg(
  key: string,
  organizationId: string,
): boolean {
  const safeOrg = organizationId.replace(/[^a-zA-Z0-9_-]/g, '')
  if (!safeOrg || key.includes('..')) return false
  return key.startsWith(`exports/orgs/${safeOrg}/`)
}
