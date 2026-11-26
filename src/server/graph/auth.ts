import crypto from 'node:crypto'
import { importPKCS8, SignJWT } from 'jose'
import { getCloudflareEnv } from '~/server/cf/env'
import { kvDelete, kvGetJson, kvPutJson } from '~/server/cf/kv'
import { getConfig } from '~/server/config'
import { decryptSecret, encryptSecret } from '~/server/security/crypto'
import { getStoredEntraSetup } from '~/server/setup/service'

interface CachedToken {
  accessToken: string
  expiresAt: number
}

interface EncryptedKvToken {
  tokenEnc: string
  expiresAt: number
}

const REFRESH_MARGIN_MS = 5 * 60 * 1000 // Refresh 5 minutes before expiry

export function thumbprintHexToX5t(hexThumbprint: string): string {
  const normalized = hexThumbprint.trim().replace(/[:\s]/g, '')
  if (!/^[0-9a-fA-F]{40}$/.test(normalized)) {
    throw new Error(
      'GRAPH_CERT_THUMBPRINT must be a 40-character hex SHA-1 thumbprint.',
    )
  }
  return Buffer.from(normalized, 'hex').toString('base64url')
}

export async function createClientAssertionJwt(params: {
  clientId: string
  tokenUrl: string
  thumbprintHex: string
  privateKeyPem: string
}): Promise<string> {
  const x5t = thumbprintHexToX5t(params.thumbprintHex)
  const key = await importPKCS8(params.privateKeyPem, 'RS256')
  const nowSeconds = Math.floor(Date.now() / 1000)

  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', x5t })
    .setIssuer(params.clientId)
    .setSubject(params.clientId)
    .setAudience(params.tokenUrl)
    .setJti(crypto.randomUUID())
    .setNotBefore(nowSeconds - 10)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + 300)
    .sign(key)
}

export interface TenantGraphCredentials {
  organizationId?: string
  entraTenantId: string
  clientId: string
  clientSecret?: string
  certThumbprint?: string
  certPrivateKey?: string
}

export class GraphTokenProvider {
  private cache: CachedToken | null = null
  private inFlight: Promise<string> | null = null
  private readonly fetchImpl: typeof fetch
  private readonly overrideCredentials?: TenantGraphCredentials

  constructor(
    fetchImpl: typeof fetch = fetch,
    overrideCredentials?: TenantGraphCredentials,
  ) {
    this.fetchImpl = fetchImpl
    this.overrideCredentials = overrideCredentials
  }

  private async resolveCredentialsAsync(): Promise<TenantGraphCredentials> {
    if (this.overrideCredentials) {
      return this.overrideCredentials
    }
    const cfg = getConfig()
    if (
      cfg.entraTenantId &&
      cfg.graphClientId &&
      (cfg.graphClientSecret ||
        (cfg.graphCertThumbprint && cfg.graphCertPrivateKey))
    ) {
      return {
        entraTenantId: cfg.entraTenantId,
        clientId: cfg.graphClientId,
        clientSecret: cfg.graphClientSecret,
        certThumbprint: cfg.graphCertThumbprint,
        certPrivateKey: cfg.graphCertPrivateKey,
      }
    }

    const stored = await getStoredEntraSetup()
    if (stored && stored.entraTenantId) {
      const hasCert = Boolean(
        stored.graphCertThumbprint && stored.graphCertPrivateKeyEnc,
      )
      const secretEnc =
        stored.graphClientSecretEnc ||
        (!hasCert ? stored.oidcClientSecretEnc : null)
      return {
        entraTenantId: stored.entraTenantId,
        clientId: stored.graphClientId || stored.oidcClientId,
        clientSecret: secretEnc ? decryptSecret(secretEnc) : undefined,
        certThumbprint: stored.graphCertThumbprint || undefined,
        certPrivateKey: stored.graphCertPrivateKeyEnc
          ? decryptSecret(stored.graphCertPrivateKeyEnc)
          : undefined,
      }
    }

    return {
      entraTenantId: cfg.entraTenantId,
      clientId: cfg.graphClientId,
      clientSecret: cfg.graphClientSecret,
      certThumbprint: cfg.graphCertThumbprint,
      certPrivateKey: cfg.graphCertPrivateKey,
    }
  }

  private getKvCacheKey(creds: TenantGraphCredentials): string {
    const orgScope = creds.organizationId || 'default'
    return `graph:tok:${orgScope}:${creds.entraTenantId}:${creds.clientId}`
  }

  public invalidate(): void {
    this.cache = null
    if (getCloudflareEnv().POCKET365_KV) {
      void this.resolveCredentialsAsync().then((creds) => {
        if (creds.entraTenantId && creds.clientId) {
          return kvDelete(this.getKvCacheKey(creds))
        }
      })
    }
  }

  public async getAccessToken(forceRefresh = false): Promise<string> {
    if (
      !forceRefresh &&
      this.cache &&
      this.cache.expiresAt - REFRESH_MARGIN_MS > Date.now()
    ) {
      return this.cache.accessToken
    }

    // Check Cloudflare KV shared token cache across edge isolates (encrypted at rest)
    if (!forceRefresh && getCloudflareEnv().POCKET365_KV) {
      const creds = await this.resolveCredentialsAsync()
      if (creds.entraTenantId && creds.clientId) {
        const kvHit = await kvGetJson<EncryptedKvToken>(this.getKvCacheKey(creds))
        if (kvHit && kvHit.expiresAt - REFRESH_MARGIN_MS > Date.now()) {
          try {
            const accessToken = decryptSecret(kvHit.tokenEnc)
            this.cache = { accessToken, expiresAt: kvHit.expiresAt }
            return accessToken
          } catch {
            // Fall through to re-acquire if decryption fails
          }
        }
      }
    }

    if (this.inFlight) {
      return this.inFlight
    }

    this.inFlight = this.acquireToken().finally(() => {
      this.inFlight = null
    })

    return this.inFlight
  }

  private async acquireToken(): Promise<string> {
    const creds = await this.resolveCredentialsAsync()

    if (!creds.entraTenantId || !creds.clientId) {
      throw new Error(
        'Microsoft Graph app-only authentication is not configured (missing ENTRA_TENANT_ID or GRAPH_CLIENT_ID).',
      )
    }

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(creds.entraTenantId)}/oauth2/v2.0/token`
    const body = new URLSearchParams({
      client_id: creds.clientId,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials',
    })

    if (creds.certThumbprint && creds.certPrivateKey) {
      const assertion = await createClientAssertionJwt({
        clientId: creds.clientId,
        tokenUrl,
        thumbprintHex: creds.certThumbprint,
        privateKeyPem: creds.certPrivateKey,
      })
      body.set(
        'client_assertion_type',
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      )
      body.set('client_assertion', assertion)
    } else if (creds.clientSecret) {
      body.set('client_secret', creds.clientSecret)
    } else {
      throw new Error(
        'Microsoft Graph credentials missing. Configure GRAPH_CLIENT_SECRET or GRAPH_CERT_THUMBPRINT + GRAPH_CERT_PRIVATE_KEY.',
      )
    }

    const response = await this.fetchImpl(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })

    const data = (await response.json().catch(() => ({}))) as {
      access_token?: string
      expires_in?: number
      error?: string
      error_description?: string
    }

    if (!response.ok || !data.access_token) {
      throw new Error(
        data.error_description ||
          data.error ||
          `Failed to acquire Microsoft Graph token (HTTP ${response.status}).`,
      )
    }

    const expiresInSeconds =
      typeof data.expires_in === 'number' && data.expires_in > 0
        ? data.expires_in
        : 3600

    const expiresAt = Date.now() + expiresInSeconds * 1000
    this.cache = {
      accessToken: data.access_token,
      expiresAt,
    }

    if (getCloudflareEnv().POCKET365_KV && expiresInSeconds > 180) {
      const kvPayload: EncryptedKvToken = {
        tokenEnc: encryptSecret(data.access_token),
        expiresAt,
      }
      await kvPutJson(
        this.getKvCacheKey(creds),
        kvPayload,
        Math.max(60, expiresInSeconds - 120),
      )
    }

    return data.access_token
  }
}

let defaultProvider: GraphTokenProvider | null = null

export function getGraphTokenProvider(): GraphTokenProvider {
  if (!defaultProvider) {
    defaultProvider = new GraphTokenProvider()
  }
  return defaultProvider
}
