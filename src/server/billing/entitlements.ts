import { setResponseStatus } from '@tanstack/react-start/server'
import { eq } from 'drizzle-orm'
import { importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose'
import { getConfig } from '~/server/config'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { licenseState, type PlanTier } from '~/server/db/schema'
import { encryptSecret } from '~/server/security/crypto'

export type EntitlementFeature =
  | 'core.directory'
  | 'core.signins'
  | 'core.mfa_basic'
  | 'core.audit'
  | 'cis.benchmarks'
  | 'cis.autofix'
  | 'users.onboarding'
  | 'users.offboarding'
  | 'mailboxes.bec_sweep'
  | 'apps.oauth'
  | 'cleanup.stale'
  | 'alerts.webhooks'
  | 'rbac.granular'
  | 'tenants.multi_tenant'
  | 'posture.ca_drift'
  | 'posture.devices_bitlocker'
  | 'posture.risky_users'
  | 'compliance.siem_export'
  | 'branding.white_label'

export interface TierDefinition {
  tier: PlanTier
  name: string
  tagline: string
  maxTenants: number
  maxUsers: number
  maxWebhooks: number
  auditRetentionDays: number
  features: EntitlementFeature[]
}

const COMMUNITY_FEATURES: EntitlementFeature[] = [
  'core.directory',
  'core.signins',
  'core.mfa_basic',
  'core.audit',
]

const PRO_FEATURES: EntitlementFeature[] = [
  ...COMMUNITY_FEATURES,
  'cis.benchmarks',
  'cis.autofix',
  'users.onboarding',
  'users.offboarding',
  'mailboxes.bec_sweep',
  'apps.oauth',
  'cleanup.stale',
  'alerts.webhooks',
  'rbac.granular',
  'posture.ca_drift',
  'posture.devices_bitlocker',
  'posture.risky_users',
  'compliance.siem_export',
]

const ENTERPRISE_FEATURES: EntitlementFeature[] = [
  ...PRO_FEATURES,
  'tenants.multi_tenant',
  'branding.white_label',
]

export const TIER_CATALOG: Record<PlanTier, TierDefinition> = {
  community: {
    tier: 'community',
    name: 'Community / Self-Hosted Free',
    tagline: 'Core single-tenant Entra ID & M365 operations on your Cloudflare account',
    maxTenants: 1,
    maxUsers: 50,
    maxWebhooks: 0,
    auditRetentionDays: 30,
    features: COMMUNITY_FEATURES,
  },
  pro: {
    tier: 'pro',
    name: 'Pro Single-Tenant',
    tagline: 'Full single-tenant CIS hardening, BEC sweeps, alerts, onboarding & posture',
    maxTenants: 1,
    maxUsers: 2500,
    maxWebhooks: 10,
    auditRetentionDays: 365,
    features: PRO_FEATURES,
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Pocket365 Cloud SaaS (MSP)',
    tagline: 'All features + unlimited multi-tenant MSP command center & white-label',
    maxTenants: 500,
    maxUsers: 100000,
    maxWebhooks: 100,
    auditRetentionDays: 2555,
    features: ENTERPRISE_FEATURES,
  },
}

export class EntitlementHttpError extends Error {
  public readonly status = 402
  public readonly requiredFeature: EntitlementFeature
  public readonly currentTier: PlanTier

  constructor(feature: EntitlementFeature, currentTier: PlanTier) {
    super(
      `Feature "${feature}" requires a higher Pocket365 tier (current plan: ${currentTier}). Visit /billing to upgrade or apply a license key.`,
    )
    this.name = 'EntitlementHttpError'
    this.requiredFeature = feature
    this.currentTier = currentTier
  }
}

export interface SignedLicenseClaims {
  tier: PlanTier
  licensee: string
  maxTenants: number
  maxUsers: number
  expiresAt: number
}

const LICENSE_ISSUER = 'pocket365-licensing'
const GRACE_PERIOD_SECONDS = 7 * 24 * 60 * 60 // 7 days

export async function issueSignedLicenseKey(
  claims: {
    tier: PlanTier
    licensee: string
    maxTenants?: number
    maxUsers?: number
    expiresInDays?: number
  },
  privateKeyPem: string,
): Promise<string> {
  const key = await importPKCS8(privateKeyPem, 'EdDSA')
  const def = TIER_CATALOG[claims.tier]
  const nowSec = Math.floor(Date.now() / 1000)
  const expSec = nowSec + (claims.expiresInDays ?? 365) * 24 * 60 * 60

  return new SignJWT({
    tier: claims.tier,
    licensee: claims.licensee,
    maxTenants: claims.maxTenants ?? def.maxTenants,
    maxUsers: claims.maxUsers ?? def.maxUsers,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT' })
    .setIssuer(LICENSE_ISSUER)
    .setSubject(claims.licensee)
    .setIssuedAt(nowSec)
    .setExpirationTime(expSec)
    .sign(key)
}

export async function verifySignedLicenseKey(
  token: string,
  publicKeyPem: string,
): Promise<SignedLicenseClaims> {
  if (!publicKeyPem) {
    throw new Error(
      'LICENSE_PUBLIC_KEY is not configured; cannot verify Ed25519 license signature.',
    )
  }
  const pubKey = await importSPKI(publicKeyPem, 'EdDSA')
  const { payload } = await jwtVerify(token.trim(), pubKey, {
    issuer: LICENSE_ISSUER,
    algorithms: ['EdDSA'],
    clockTolerance: GRACE_PERIOD_SECONDS,
  })

  const tier = payload.tier
  if (tier !== 'community' && tier !== 'pro' && tier !== 'enterprise') {
    throw new Error('License key contains an invalid tier.')
  }

  const def = TIER_CATALOG[tier]
  return {
    tier,
    licensee:
      typeof payload.licensee === 'string' && payload.licensee.trim()
        ? payload.licensee.trim()
        : 'Licensed Organization',
    maxTenants:
      typeof payload.maxTenants === 'number'
        ? payload.maxTenants
        : def.maxTenants,
    maxUsers:
      typeof payload.maxUsers === 'number' ? payload.maxUsers : def.maxUsers,
    expiresAt:
      typeof payload.exp === 'number'
        ? payload.exp * 1000
        : Date.now() + 365 * 86400_000,
  }
}

export interface ActivePlanInfo {
  tier: PlanTier
  source: 'env' | 'license_key' | 'stripe'
  enforcement: 'off' | 'strict'
  licensee: string
  maxTenants: number
  maxUsers: number
  maxWebhooks: number
  auditRetentionDays: number
  expiresAt: number | null
  inGracePeriod: boolean
  features: EntitlementFeature[]
}

export async function getActivePlan(): Promise<ActivePlanInfo> {
  const cfg = getConfig()
  const db = getDb()
  const stored = await db
    .select()
    .from(licenseState)
    .where(eq(licenseState.id, 'active'))
    .get()

  const tier: PlanTier = stored?.tier ?? cfg.defaultTier
  const now = Date.now()
  const expiresAt = stored?.expiresAt ?? null
  const expired = expiresAt !== null && expiresAt < now
  const pastGrace =
    expiresAt !== null && expiresAt + GRACE_PERIOD_SECONDS * 1000 < now

  const effectiveTier: PlanTier =
    cfg.licenseEnforcement === 'strict' && pastGrace ? 'community' : tier
  const effectiveDef = TIER_CATALOG[effectiveTier]

  return {
    tier: effectiveTier,
    source: (stored?.source as ActivePlanInfo['source']) ?? 'env',
    enforcement: cfg.licenseEnforcement,
    licensee: stored?.licensee ?? 'Self-Hosted Instance',
    maxTenants: stored?.maxTenants ?? effectiveDef.maxTenants,
    maxUsers: stored?.maxUsers ?? effectiveDef.maxUsers,
    maxWebhooks: effectiveDef.maxWebhooks,
    auditRetentionDays: effectiveDef.auditRetentionDays,
    expiresAt,
    inGracePeriod: Boolean(expired && !pastGrace),
    features: effectiveDef.features,
  }
}

export async function isFeatureEntitled(
  feature: EntitlementFeature,
): Promise<boolean> {
  const plan = await getActivePlan()
  if (plan.enforcement === 'off') {
    return true
  }
  return plan.features.includes(feature)
}

/**
 * Server-side commercial tier entitlement check.
 * When LICENSE_ENFORCEMENT=strict, throws HTTP 402 Payment Required for locked features.
 * When LICENSE_ENFORCEMENT=off, allows all features cleanly.
 */
export async function requireEntitlement(
  feature: EntitlementFeature,
  actor?: { oid: string; upn: string; role: string },
): Promise<ActivePlanInfo> {
  const plan = await getActivePlan()
  if (plan.enforcement === 'off' || plan.features.includes(feature)) {
    return plan
  }

  try {
    setResponseStatus(402)
  } catch {
    // Outside active TanStack Start request context
  }

  if (actor) {
    await recordAuditLog({
      actorOid: actor.oid,
      actorUpn: actor.upn,
      actorRole: actor.role,
      action: `entitlement.denied:${feature}`,
      target: plan.tier,
      status: 'failure',
      details: { requiredFeature: feature, currentTier: plan.tier },
    })
  }

  throw new EntitlementHttpError(feature, plan.tier)
}

export async function persistLicenseState(params: {
  source: 'env' | 'license_key' | 'stripe'
  tier: PlanTier
  licensee: string
  rawLicenseKey?: string
  stripeCustomerId?: string | null
  stripeSubscriptionId?: string | null
  maxTenants?: number
  maxUsers?: number
  expiresAt?: number | null
  updatedBy: string
}): Promise<void> {
  const db = getDb()
  const def = TIER_CATALOG[params.tier]
  const now = Date.now()
  const row = {
    id: 'active',
    source: params.source,
    tier: params.tier,
    licensee: params.licensee,
    licenseKeyEnc: params.rawLicenseKey
      ? encryptSecret(params.rawLicenseKey)
      : null,
    stripeCustomerId: params.stripeCustomerId ?? null,
    stripeSubscriptionId: params.stripeSubscriptionId ?? null,
    maxTenants: params.maxTenants ?? def.maxTenants,
    maxUsers: params.maxUsers ?? def.maxUsers,
    expiresAt: params.expiresAt ?? null,
    updatedBy: params.updatedBy,
    updatedAt: now,
  }

  await db
    .insert(licenseState)
    .values(row)
    .onConflictDoUpdate({
      target: licenseState.id,
      set: row,
    })
    .run()
}
