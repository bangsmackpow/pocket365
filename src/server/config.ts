import { getRuntimeEnvVar } from '~/server/cf/env'

export type DeploymentMode = 'self_hosted' | 'saas'

export interface Pocket365Config {
  deploymentMode: DeploymentMode
  appBaseUrl: string
  entraTenantId: string
  oidcClientId: string
  oidcClientSecret: string
  sessionSecret: string
  dataEncryptionKey: string
  setupBootstrapToken: string
  sessionTtlHours: number
  sessionIdleTimeoutMinutes: number
  allowPrivateWebhooks: boolean
  trustedProxyHops: number
  ownerEntries: string[]
  adminEntries: string[]
  helpdeskEntries: string[]
  auditorEntries: string[]
  viewerEntries: string[]
  graphClientId: string
  graphClientSecret: string
  graphCertThumbprint: string
  graphCertPrivateKey: string
  graphMaxRetries: number
  graphBaseBackoffMs: number
  licenseEnforcement: 'off' | 'strict'
  defaultTier: 'community' | 'pro' | 'enterprise'
  licensePublicKeyPem: string
  licenseKey: string
  stripeSecretKey: string
  stripeWebhookSecret: string
  stripePricePro: string
  stripePriceEnterprise: string
  stripePriceSaas: string
}

export interface ConfigReadiness {
  deploymentMode: DeploymentMode
  singleTenantConfigured: boolean
  oidcConfigured: boolean
  sessionSecretConfigured: boolean
  encryptionKeyConfigured: boolean
  rbacConfigured: boolean
  graphConfigured: boolean
  graphAuthMode: 'certificate' | 'client_secret' | 'unconfigured'
  appBaseUrlHttps: boolean
}

function parseCsvList(raw: string | undefined): string[] {
  if (!raw) return []
  return raw
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean)
}

function normalizeBaseUrl(raw: string | undefined): string {
  const value = (raw || 'http://localhost:3000').trim()
  return value.replace(/\/+$/, '')
}

function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
  min = 1,
  max = 100000,
): number {
  if (!raw) return fallback
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) {
    return fallback
  }
  return parsed
}

/**
 * Reads live configuration from Cloudflare Worker bindings (`globalThis.__env__`)
 * or `process.env`. Intentionally lightweight so per-request Worker env bindings
 * are always respected without stale cross-isolate caching.
 */
export function getConfig(): Pocket365Config {
  const env = (key: string) => getRuntimeEnvVar(key)

  const rawMode = (env('DEPLOYMENT_MODE') || '').trim().toLowerCase()
  const deploymentMode: DeploymentMode =
    rawMode === 'saas' ? 'saas' : 'self_hosted'

  const appBaseUrl = normalizeBaseUrl(env('APP_BASE_URL'))

  const entraTenantId = (env('ENTRA_TENANT_ID') || '').trim()
  const oidcClientId = (env('OIDC_CLIENT_ID') || '').trim()
  const oidcClientSecret = (env('OIDC_CLIENT_SECRET') || '').trim()
  const sessionSecret = (env('SESSION_SECRET') || '').trim()
  const dataEncryptionKey = (env('DATA_ENCRYPTION_KEY') || '').trim()
  const setupBootstrapToken = (env('SETUP_BOOTSTRAP_TOKEN') || '').trim()
  const sessionTtlHours = parsePositiveInt(env('SESSION_TTL_HOURS'), 12, 1, 720)
  const sessionIdleTimeoutMinutes = parsePositiveInt(
    env('SESSION_IDLE_TIMEOUT_MINUTES'),
    120,
    5,
    10080,
  )
  const allowPrivateWebhooks =
    (env('ALLOW_PRIVATE_WEBHOOKS') || '').trim().toLowerCase() === 'true'
  const trustedProxyHops = parsePositiveInt(env('TRUSTED_PROXY_HOPS'), 1, 0, 10)

  const ownerEntries = parseCsvList(env('OWNER_OIDS_OR_GROUPS'))
  const adminEntries = parseCsvList(env('ADMIN_OIDS_OR_GROUPS'))
  const helpdeskEntries = parseCsvList(env('HELPDESK_OIDS_OR_GROUPS'))
  const auditorEntries = parseCsvList(env('AUDITOR_OIDS_OR_GROUPS'))
  const viewerEntries = parseCsvList(env('VIEWER_OIDS_OR_GROUPS'))

  const graphClientId = (env('GRAPH_CLIENT_ID') || oidcClientId).trim()
  const graphClientSecret = (env('GRAPH_CLIENT_SECRET') || '').trim()
  const graphCertThumbprint = (env('GRAPH_CERT_THUMBPRINT') || '')
    .trim()
    .replace(/[:\s]/g, '')
  const graphCertPrivateKey = (env('GRAPH_CERT_PRIVATE_KEY') || '')
    .trim()
    .replace(/\\n/g, '\n')

  const graphMaxRetries = parsePositiveInt(env('GRAPH_MAX_RETRIES'), 4, 0, 10)
  const graphBaseBackoffMs = parsePositiveInt(
    env('GRAPH_BASE_BACKOFF_MS'),
    1000,
    50,
    30000,
  )

  const rawEnforcement = (env('LICENSE_ENFORCEMENT') || '').trim().toLowerCase()
  const licenseEnforcement =
    rawEnforcement === 'off'
      ? 'off'
      : rawEnforcement === 'strict' || deploymentMode === 'saas'
        ? 'strict'
        : 'off'
  const rawTier = (env('POCKET365_TIER') || '').trim().toLowerCase()
  const defaultTier: 'community' | 'pro' | 'enterprise' =
    rawTier === 'community' || rawTier === 'pro' || rawTier === 'enterprise'
      ? rawTier
      : licenseEnforcement === 'strict'
        ? 'community'
        : 'enterprise'
  const licensePublicKeyPem = (env('LICENSE_PUBLIC_KEY') || '')
    .trim()
    .replace(/\\n/g, '\n')
  const licenseKey = (env('POCKET365_LICENSE_KEY') || '').trim()
  const stripeSecretKey = (env('STRIPE_SECRET_KEY') || '').trim()
  const stripeWebhookSecret = (env('STRIPE_WEBHOOK_SECRET') || '').trim()
  const stripePricePro = (env('STRIPE_PRICE_PRO') || '').trim()
  const stripePriceEnterprise = (env('STRIPE_PRICE_ENTERPRISE') || '').trim()
  const stripePriceSaas = (
    env('STRIPE_PRICE_SAAS') ||
    stripePriceEnterprise ||
    stripePricePro
  ).trim()

  return {
    deploymentMode,
    appBaseUrl,
    entraTenantId,
    oidcClientId,
    oidcClientSecret,
    sessionSecret,
    dataEncryptionKey,
    setupBootstrapToken,
    sessionTtlHours,
    sessionIdleTimeoutMinutes,
    allowPrivateWebhooks,
    trustedProxyHops,
    ownerEntries,
    adminEntries,
    helpdeskEntries,
    auditorEntries,
    viewerEntries,
    graphClientId,
    graphClientSecret,
    graphCertThumbprint,
    graphCertPrivateKey,
    graphMaxRetries,
    graphBaseBackoffMs,
    licenseEnforcement,
    defaultTier,
    licensePublicKeyPem,
    licenseKey,
    stripeSecretKey,
    stripeWebhookSecret,
    stripePricePro,
    stripePriceEnterprise,
    stripePriceSaas,
  }
}

export function resetConfigCache(): void {
  // No-op: getConfig() reads live Worker env / process.env per call
}

export function getConfigReadiness(): ConfigReadiness {
  const cfg = getConfig()
  const hasCertAuth = Boolean(
    cfg.graphClientId && cfg.graphCertThumbprint && cfg.graphCertPrivateKey,
  )
  const hasSecretAuth = Boolean(cfg.graphClientId && cfg.graphClientSecret)

  const oidcConfigured =
    cfg.deploymentMode === 'saas'
      ? Boolean(cfg.oidcClientId && cfg.oidcClientSecret)
      : Boolean(cfg.entraTenantId && cfg.oidcClientId && cfg.oidcClientSecret)

  const graphConfigured =
    cfg.deploymentMode === 'saas'
      ? Boolean(hasCertAuth || hasSecretAuth)
      : Boolean(cfg.entraTenantId && (hasCertAuth || hasSecretAuth))

  return {
    deploymentMode: cfg.deploymentMode,
    singleTenantConfigured: Boolean(cfg.entraTenantId),
    oidcConfigured,
    sessionSecretConfigured: cfg.sessionSecret.length >= 32,
    encryptionKeyConfigured: cfg.dataEncryptionKey.length >= 32,
    rbacConfigured:
      cfg.deploymentMode === 'saas' ||
      cfg.ownerEntries.length > 0 ||
      cfg.adminEntries.length > 0 ||
      cfg.helpdeskEntries.length > 0 ||
      cfg.auditorEntries.length > 0 ||
      cfg.viewerEntries.length > 0,
    graphConfigured,
    graphAuthMode: hasCertAuth
      ? 'certificate'
      : hasSecretAuth
        ? 'client_secret'
        : 'unconfigured',
    appBaseUrlHttps: cfg.appBaseUrl.startsWith('https://'),
  }
}
