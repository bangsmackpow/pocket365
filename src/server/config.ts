import fs from 'node:fs'
import path from 'node:path'

export interface Pocket365Config {
  port: number
  host: string
  appBaseUrl: string
  dataDir: string
  entraTenantId: string
  oidcClientId: string
  oidcClientSecret: string
  sessionSecret: string
  sessionTtlHours: number
  adminEntries: string[]
  viewerEntries: string[]
  graphClientId: string
  graphClientSecret: string
  graphCertThumbprint: string
  graphCertPrivateKey: string
  graphMaxRetries: number
  graphBaseBackoffMs: number
}

export interface ConfigReadiness {
  singleTenantConfigured: boolean
  oidcConfigured: boolean
  sessionSecretConfigured: boolean
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

function normalizeBaseUrl(raw: string | undefined, port: number): string {
  const value = (raw || `http://localhost:${port}`).trim()
  return value.replace(/\/+$/, '')
}

function loadPrivateKey(env: NodeJS.ProcessEnv): string {
  const inline = env.GRAPH_CERT_PRIVATE_KEY?.trim()
  if (inline) {
    return inline.replace(/\\n/g, '\n')
  }
  const keyPath = env.GRAPH_CERT_PRIVATE_KEY_PATH?.trim()
  if (keyPath && fs.existsSync(keyPath)) {
    return fs.readFileSync(keyPath, 'utf8')
  }
  return ''
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

let cachedConfig: Pocket365Config | null = null

export function getConfig(): Pocket365Config {
  if (cachedConfig) return cachedConfig

  const env = process.env
  const port = parsePositiveInt(env.PORT, 3000, 1, 65535)
  const host = (env.HOST || '0.0.0.0').trim()
  const appBaseUrl = normalizeBaseUrl(env.APP_BASE_URL, port)
  const dataDir = path.resolve(env.DATA_DIR?.trim() || './data')

  const entraTenantId = (env.ENTRA_TENANT_ID || '').trim()
  const oidcClientId = (env.OIDC_CLIENT_ID || '').trim()
  const oidcClientSecret = (env.OIDC_CLIENT_SECRET || '').trim()
  const sessionSecret = (env.SESSION_SECRET || '').trim()
  const sessionTtlHours = parsePositiveInt(env.SESSION_TTL_HOURS, 12, 1, 720)

  const adminEntries = parseCsvList(env.ADMIN_OIDS_OR_GROUPS)
  const viewerEntries = parseCsvList(env.VIEWER_OIDS_OR_GROUPS)

  const graphClientId = (env.GRAPH_CLIENT_ID || oidcClientId).trim()
  const graphClientSecret = (env.GRAPH_CLIENT_SECRET || '').trim()
  const graphCertThumbprint = (env.GRAPH_CERT_THUMBPRINT || '')
    .trim()
    .replace(/[:\s]/g, '')
  const graphCertPrivateKey = loadPrivateKey(env)

  const graphMaxRetries = parsePositiveInt(env.GRAPH_MAX_RETRIES, 4, 0, 10)
  const graphBaseBackoffMs = parsePositiveInt(
    env.GRAPH_BASE_BACKOFF_MS,
    1000,
    50,
    30000,
  )

  cachedConfig = {
    port,
    host,
    appBaseUrl,
    dataDir,
    entraTenantId,
    oidcClientId,
    oidcClientSecret,
    sessionSecret,
    sessionTtlHours,
    adminEntries,
    viewerEntries,
    graphClientId,
    graphClientSecret,
    graphCertThumbprint,
    graphCertPrivateKey,
    graphMaxRetries,
    graphBaseBackoffMs,
  }

  return cachedConfig
}

export function resetConfigCache(): void {
  cachedConfig = null
}

export function getConfigReadiness(): ConfigReadiness {
  const cfg = getConfig()
  const hasCertAuth = Boolean(
    cfg.graphClientId && cfg.graphCertThumbprint && cfg.graphCertPrivateKey,
  )
  const hasSecretAuth = Boolean(cfg.graphClientId && cfg.graphClientSecret)

  return {
    singleTenantConfigured: Boolean(cfg.entraTenantId),
    oidcConfigured: Boolean(
      cfg.entraTenantId && cfg.oidcClientId && cfg.oidcClientSecret,
    ),
    sessionSecretConfigured: cfg.sessionSecret.length >= 32,
    rbacConfigured: cfg.adminEntries.length > 0 || cfg.viewerEntries.length > 0,
    graphConfigured: Boolean(
      cfg.entraTenantId && (hasCertAuth || hasSecretAuth),
    ),
    graphAuthMode: hasCertAuth
      ? 'certificate'
      : hasSecretAuth
        ? 'client_secret'
        : 'unconfigured',
    appBaseUrlHttps: cfg.appBaseUrl.startsWith('https://'),
  }
}
