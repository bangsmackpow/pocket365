import { setResponseStatus } from '@tanstack/react-start/server'
import { eq } from 'drizzle-orm'
import { importPKCS8, importSPKI, jwtVerify, SignJWT } from 'jose'
import { getConfig, type DeploymentMode } from '~/server/config'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { licenseState, type PlanTier } from '~/server/db/schema'
import { DEFAULT_ORG_ID } from '~/server/orgs/service'
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
    tagline:
      'Core single-tenant Entra ID & M365 operations on your own Cloudflare account',
    maxTenants: 1,
    maxUsers: 50,
    maxWebhooks: 0,
    auditRetentionDays: 30,
    features: COMMUNITY_FEATURES,
  },
  pro: {
    tier: 'pro',
    name: 'Pro Single-Tenant License',
    tagline:
      'All single-tenant features (CIS fixes, BEC sweeps, alerts, onboarding, BitLocker) on your Cloudflare account',
    maxTenants: 1,
    maxUsers: 2500,
    maxWebhooks: 10,
    auditRetentionDays: 365,
    features: PRO_FEATURES,
  },
  enterprise: {
    tier: 'enterprise',
    name: 'Pocket365 Cloud SaaS (All Features + MSP)',
    tagline:
      'Single monthly subscription with all features + unlimited multi-tenant MSP command center',
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

  constructor(
    feature: EntitlementFeature,
    currentTier: PlanTier,
    customMessage?: string,
  ) {
    super(
      customMessage ||
        `Feature "${feature}" requires a higher Pocket365 plan (current tier: ${currentTier}). Visit /billing to upgrade or apply a license key.`,
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
  deploymentMode: DeploymentMode
  organizationId: string
  tier: PlanTier
  source: 'env' | 'license_key' | 'stripe'
  enforcement: 'off' | 'strict'
  licensee: string
  multiTenantEnabled: boolean
  maxTenants: number
  maxUsers: number
  maxWebhooks: number
  auditRetentionDays: number
  expiresAt: number | null
  inGracePeriod: boolean
  features: EntitlementFeature[]
}

function licenseRowId(organizationId: string): string {
  return organizationId === DEFAULT_ORG_ID ? 'active' : `org:${organizationId}`
}

export async function getActivePlan(
  organizationId = DEFAULT_ORG_ID,
): Promise<ActivePlanInfo> {
  const cfg = getConfig()
  const db = getDb()
  const rowId = licenseRowId(organizationId)
  const stored = await db
    .select()
    .from(licenseState)
    .where(eq(licenseState.id, rowId))
    .get()

  const rawTier: PlanTier =
    stored?.tier ??
    (cfg.deploymentMode === 'saas' ? 'community' : cfg.defaultTier)

  const now = Date.now()
  const expiresAt = stored?.expiresAt ?? null
  const expired = expiresAt !== null && expiresAt < now
  const pastGrace =
    expiresAt !== null && expiresAt + GRACE_PERIOD_SECONDS * 1000 < now

  let effectiveTier: PlanTier =
    cfg.licenseEnforcement === 'strict' && pastGrace ? 'community' : rawTier

  // Self-hosted deployments are strictly single-tenant (capped at Pro features)
  if (cfg.deploymentMode === 'self_hosted' && effectiveTier === 'enterprise') {
    effectiveTier = 'pro'
  }

  const effectiveDef = TIER_CATALOG[effectiveTier]
  const multiTenantEnabled =
    cfg.deploymentMode === 'saas' && effectiveTier === 'enterprise'
  const features = multiTenantEnabled
    ? effectiveDef.features
    : effectiveDef.features.filter((f) => f !== 'tenants.multi_tenant')

  return {
    deploymentMode: cfg.deploymentMode,
    organizationId,
    tier: effectiveTier,
    source: (stored?.source as ActivePlanInfo['source']) ?? 'env',
    enforcement: cfg.licenseEnforcement,
    licensee:
      stored?.licensee ??
      (cfg.deploymentMode === 'saas'
        ? 'Cloud SaaS Organization'
        : 'Self-Hosted Instance'),
    multiTenantEnabled,
    maxTenants: multiTenantEnabled
      ? (stored?.maxTenants ?? effectiveDef.maxTenants)
      : 1,
    maxUsers: stored?.maxUsers ?? effectiveDef.maxUsers,
    maxWebhooks: effectiveDef.maxWebhooks,
    auditRetentionDays: effectiveDef.auditRetentionDays,
    expiresAt,
    inGracePeriod: Boolean(expired && !pastGrace),
    features,
  }
}

export async function isFeatureEntitled(
  feature: EntitlementFeature,
  organizationId = DEFAULT_ORG_ID,
): Promise<boolean> {
  const plan = await getActivePlan(organizationId)
  if (feature === 'tenants.multi_tenant' && plan.deploymentMode !== 'saas') {
    return false
  }
  if (plan.enforcement === 'off') {
    return true
  }
  return plan.features.includes(feature)
}

/**
 * Server-side commercial tier & deployment mode entitlement check.
 * - Multi-tenant MSP features (`tenants.multi_tenant`) are strictly gated to `DEPLOYMENT_MODE=saas`
 *   with an active SaaS subscription.
 * - When LICENSE_ENFORCEMENT=strict (or DEPLOYMENT_MODE=saas), throws HTTP 402 Payment Required.
 */
export async function requireEntitlement(
  feature: EntitlementFeature,
  actor?: {
    oid: string
    upn: string
    role: string
    organizationId?: string
  },
): Promise<ActivePlanInfo> {
  const orgId = actor?.organizationId || DEFAULT_ORG_ID
  const plan = await getActivePlan(orgId)

  if (feature === 'tenants.multi_tenant' && plan.deploymentMode !== 'saas') {
    try {
      setResponseStatus(402)
    } catch {
      // Outside request context
    }
    if (actor) {
      await recordAuditLog({
        organizationId: orgId,
        actorOid: actor.oid,
        actorUpn: actor.upn,
        actorRole: actor.role,
        action: `entitlement.denied:${feature}`,
        target: 'self_hosted_mode',
        status: 'failure',
        details: {
          requiredFeature: feature,
          deploymentMode: plan.deploymentMode,
        },
      })
    }
    throw new EntitlementHttpError(
      feature,
      plan.tier,
      'Multi-tenant MSP management is exclusive to Pocket365 Cloud SaaS (DEPLOYMENT_MODE=saas). Self-hosted deployments are single-tenant.',
    )
  }

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
      organizationId: orgId,
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
  organizationId?: string
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
  const orgId = params.organizationId?.trim() || DEFAULT_ORG_ID
  const def = TIER_CATALOG[params.tier]
  const now = Date.now()
  const row = {
    id: licenseRowId(orgId),
    organizationId: orgId,
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
