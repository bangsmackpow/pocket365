import crypto from 'node:crypto'
import { eq, lt } from 'drizzle-orm'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { getDb } from '~/server/db'
import { oidcStates } from '~/server/db/schema'
import { buildCanonicalUrl, sanitizeReturnTo } from '~/server/http/proxy'
import { getEffectiveEntraConfig } from '~/server/setup/service'

const OIDC_STATE_TTL_MS = 10 * 60 * 1000 // 10 minutes

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function getTenantJwks(tenantId: string): ReturnType<typeof createRemoteJWKSet> {
  const existing = jwksCache.get(tenantId)
  if (existing) return existing
  const jwksUri = new URL(
    `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/discovery/v2.0/keys`,
  )
  const jwks = createRemoteJWKSet(jwksUri)
  jwksCache.set(tenantId, jwks)
  return jwks
}

export function sha256Base64Url(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('base64url')
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

export function getEntraEndpoints(tenantId: string) {
  const encodedTenant = encodeURIComponent(tenantId)
  const base = `https://login.microsoftonline.com/${encodedTenant}`
  return {
    issuer: `${base}/v2.0`,
    authorizeUrl: `${base}/oauth2/v2.0/authorize`,
    tokenUrl: `${base}/oauth2/v2.0/token`,
    jwksUrl: `${base}/discovery/v2.0/keys`,
    endSessionUrl: `${base}/oauth2/v2.0/logout`,
  }
}

export interface OidcLoginInitResult {
  authorizationUrl: string
  cookieBindingToken: string
  state: string
}

export async function createOidcLoginTransaction(
  returnToRaw?: string | null,
  request?: Request,
): Promise<OidcLoginInitResult> {
  const effective = await getEffectiveEntraConfig()
  if (
    !effective.entraTenantId ||
    !effective.oidcClientId ||
    !effective.oidcClientSecret
  ) {
    throw new Error(
      'OIDC is not configured. Complete /setup or configure ENTRA_TENANT_ID, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET.',
    )
  }

  const db = getDb()
  const now = Date.now()

  // Opportunistically clean up expired OIDC transactions
  await db.delete(oidcStates).where(lt(oidcStates.expiresAt, now)).run()

  const state = crypto.randomBytes(32).toString('base64url')
  const nonce = crypto.randomBytes(32).toString('base64url')
  const codeVerifier = crypto.randomBytes(64).toString('base64url')
  const codeChallenge = sha256Base64Url(codeVerifier)
  const cookieBindingToken = crypto.randomBytes(32).toString('base64url')
  const cookieBindingHash = sha256Base64Url(cookieBindingToken)
  const returnTo = sanitizeReturnTo(returnToRaw)

  await db
    .insert(oidcStates)
    .values({
      state,
      nonce,
      codeVerifier,
      cookieBindingHash,
      returnTo,
      expiresAt: now + OIDC_STATE_TTL_MS,
      createdAt: now,
    })
    .run()

  const endpoints = getEntraEndpoints(effective.entraTenantId)
  const redirectUri = buildCanonicalUrl('/api/auth/callback', request)

  const params = new URLSearchParams({
    client_id: effective.oidcClientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  return {
    authorizationUrl: `${endpoints.authorizeUrl}?${params.toString()}`,
    cookieBindingToken,
    state,
  }
}

export interface VerifiedOidcIdentity {
  oid: string
  upn: string
  preferredUsername?: string
  email?: string
  displayName: string
  groups: string[]
  hasGroupsOverage: boolean
  returnTo: string
}

export interface VerifyIdTokenParams {
  idToken: string
  expectedNonce: string
  tenantId: string
  clientId: string
  jwks?: ReturnType<typeof createRemoteJWKSet> | Parameters<typeof jwtVerify>[1]
}

export async function verifyEntraIdToken(
  params: VerifyIdTokenParams,
): Promise<{
  oid: string
  upn: string
  preferredUsername?: string
  email?: string
  displayName: string
  groups: string[]
  hasGroupsOverage: boolean
}> {
  const endpoints = getEntraEndpoints(params.tenantId)
  const keyResolver = params.jwks ?? getTenantJwks(params.tenantId)

  const { payload } = await jwtVerify(
    params.idToken,
    keyResolver as Parameters<typeof jwtVerify>[1],
    {
      issuer: endpoints.issuer,
      audience: params.clientId,
      algorithms: ['RS256'],
      clockTolerance: 30,
    },
  )

  // Strict single-tenant check
  const tid = typeof payload.tid === 'string' ? payload.tid : ''
  if (!tid || tid.toLowerCase() !== params.tenantId.toLowerCase()) {
    throw new Error('ID token tenant (tid) does not match configured ENTRA_TENANT_ID.')
  }

  // Strict nonce validation
  const tokenNonce = typeof payload.nonce === 'string' ? payload.nonce : ''
  if (!tokenNonce || !constantTimeEquals(tokenNonce, params.expectedNonce)) {
    throw new Error('ID token nonce mismatch.')
  }

  const oid = typeof payload.oid === 'string' ? payload.oid : ''
  if (!oid) {
    throw new Error('ID token is missing required Entra object identifier (oid).')
  }

  const preferredUsername =
    typeof payload.preferred_username === 'string'
      ? payload.preferred_username
      : undefined
  const upnClaim = typeof payload.upn === 'string' ? payload.upn : undefined
  const email = typeof payload.email === 'string' ? payload.email : undefined
  const upn = preferredUsername || upnClaim || email || oid
  const displayName =
    typeof payload.name === 'string' && payload.name.trim()
      ? payload.name.trim()
      : upn

  const groups = Array.isArray(payload.groups)
    ? payload.groups.filter((g): g is string => typeof g === 'string')
    : []

  const claimNames =
    payload._claim_names && typeof payload._claim_names === 'object'
      ? (payload._claim_names as Record<string, unknown>)
      : undefined

  const hasGroupsOverage = Boolean(
    payload.hasgroups === true ||
      payload.hasgroups === 'true' ||
      (claimNames && 'groups' in claimNames),
  )

  return {
    oid,
    upn,
    preferredUsername,
    email,
    displayName,
    groups,
    hasGroupsOverage,
  }
}

export async function completeOidcCallback(params: {
  code: string
  state: string
  cookieBindingToken: string
  request?: Request
}): Promise<VerifiedOidcIdentity> {
  const effective = await getEffectiveEntraConfig()
  if (
    !effective.entraTenantId ||
    !effective.oidcClientId ||
    !effective.oidcClientSecret
  ) {
    throw new Error('OIDC configuration is incomplete.')
  }

  const db = getDb()
  const tx = await db
    .select()
    .from(oidcStates)
    .where(eq(oidcStates.state, params.state))
    .get()

  // Always delete state immediately so it is strictly single-use
  if (tx) {
    await db.delete(oidcStates).where(eq(oidcStates.state, params.state)).run()
  }

  if (!tx) {
    throw new Error('Invalid or already consumed OIDC state parameter.')
  }

  if (tx.expiresAt < Date.now()) {
    throw new Error('OIDC login transaction has expired. Please try again.')
  }

  const providedHash = sha256Base64Url(params.cookieBindingToken)
  if (
    !params.cookieBindingToken ||
    !constantTimeEquals(providedHash, tx.cookieBindingHash)
  ) {
    throw new Error('OIDC browser binding cookie validation failed.')
  }

  const endpoints = getEntraEndpoints(effective.entraTenantId)
  const redirectUri = buildCanonicalUrl('/api/auth/callback', params.request)

  const tokenBody = new URLSearchParams({
    client_id: effective.oidcClientId,
    client_secret: effective.oidcClientSecret,
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: redirectUri,
    code_verifier: tx.codeVerifier,
    scope: 'openid profile email',
  })

  const tokenRes = await fetch(endpoints.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenBody.toString(),
  })

  const tokenPayload = (await tokenRes.json().catch(() => ({}))) as {
    id_token?: string
    error?: string
    error_description?: string
  }

  if (!tokenRes.ok || !tokenPayload.id_token) {
    throw new Error(
      tokenPayload.error_description ||
        tokenPayload.error ||
        `Entra token exchange failed (${tokenRes.status}).`,
    )
  }

  const verified = await verifyEntraIdToken({
    idToken: tokenPayload.id_token,
    expectedNonce: tx.nonce,
    tenantId: effective.entraTenantId,
    clientId: effective.oidcClientId,
  })

  return {
    ...verified,
    returnTo: sanitizeReturnTo(tx.returnTo),
  }
}
