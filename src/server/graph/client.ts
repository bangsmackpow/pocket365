import { getConfig } from '~/server/config'
import { getGraphTokenProvider, type GraphTokenProvider } from './auth'

const GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0'
const RETRYABLE_STATUSES = new Set([429, 502, 503, 504])
const MAX_BACKOFF_MS = 60_000

export class GraphApiError extends Error {
  public readonly status: number
  public readonly code: string
  public readonly requestId?: string

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message)
    this.name = 'GraphApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
  }
}

export interface GraphAssignedLicense {
  skuId: string
  disabledPlans: string[]
}

export interface GraphUser {
  id: string
  displayName: string
  userPrincipalName: string
  mail: string | null
  accountEnabled: boolean | null
  jobTitle: string | null
  department: string | null
  officeLocation: string | null
  createdDateTime?: string | null
  assignedLicenses: GraphAssignedLicense[]
}

export interface GraphSubscribedSku {
  id: string
  skuId: string
  skuPartNumber: string
  capabilityStatus: string
  consumedUnits: number
  prepaidUnits: {
    enabled: number
    suspended: number
    warning: number
  }
}

export interface GraphGroup {
  id: string
  displayName: string
  description: string | null
  mail: string | null
  mailEnabled: boolean
  securityEnabled: boolean
  groupTypes: string[]
  createdDateTime?: string | null
}

export interface GraphGroupMember {
  id: string
  displayName: string
  userPrincipalName?: string | null
  mail?: string | null
  '@odata.type'?: string
}

export interface GraphOrganization {
  id: string
  displayName: string
  verifiedDomains: Array<{
    name: string
    isDefault: boolean
    isInitial: boolean
  }>
}

export interface GraphSignInStatus {
  errorCode: number
  failureReason: string | null
  additionalDetails: string | null
}

export interface GraphSignInDeviceDetail {
  deviceId: string | null
  displayName: string | null
  operatingSystem: string | null
  browser: string | null
  isCompliant: boolean | null
  isManaged: boolean | null
  trustType: string | null
}

export interface GraphSignInLocation {
  city: string | null
  state: string | null
  countryOrRegion: string | null
}

export interface GraphAppliedCaPolicy {
  id: string
  displayName: string
  result: string
  enforcedGrantControls?: string[]
  enforcedSessionControls?: string[]
}

export interface GraphSignIn {
  id: string
  createdDateTime: string
  userDisplayName: string | null
  userPrincipalName: string | null
  userId: string | null
  appDisplayName: string | null
  appId: string | null
  resourceDisplayName: string | null
  ipAddress: string | null
  clientAppUsed: string | null
  correlationId: string | null
  isInteractive: boolean | null
  conditionalAccessStatus: string | null
  riskLevelAggregated: string | null
  riskLevelDuringSignIn: string | null
  riskState: string | null
  status: GraphSignInStatus
  deviceDetail: GraphSignInDeviceDetail | null
  location: GraphSignInLocation | null
  appliedConditionalAccessPolicies?: GraphAppliedCaPolicy[]
}

export interface ListSignInLogsParams {
  status?: 'all' | 'failure' | 'success' | 'mfa' | 'blocked'
  user?: string
  app?: string
  ipAddress?: string
  errorCode?: number
  daysBack?: number
  top?: number
  nextLink?: string
}

export interface GraphPageResult<T> {
  items: T[]
  nextLink: string | null
}

export function parseRetryAfterMs(headerValue: string | null): number | null {
  if (!headerValue) return null
  const trimmed = headerValue.trim()
  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    const seconds = Number.parseFloat(trimmed)
    return Math.min(Math.max(Math.ceil(seconds * 1000), 100), MAX_BACKOFF_MS)
  }
  const dateMs = Date.parse(trimmed)
  if (!Number.isNaN(dateMs)) {
    const diff = dateMs - Date.now()
    return Math.min(Math.max(diff, 100), MAX_BACKOFF_MS)
  }
  return null
}

export function computeBackoffMs(
  attempt: number,
  baseBackoffMs: number,
  retryAfterHeader: string | null,
  jitterFn: () => number = Math.random,
): number {
  const retryAfterMs = parseRetryAfterMs(retryAfterHeader)
  if (retryAfterMs !== null) {
    return retryAfterMs
  }
  const exponential = baseBackoffMs * Math.pow(2, attempt)
  const jitter = Math.floor(jitterFn() * Math.min(500, exponential * 0.25))
  return Math.min(exponential + jitter, MAX_BACKOFF_MS)
}

function escapeODataString(value: string): string {
  return value.replace(/'/g, "''")
}

function escapeGraphSearch(value: string): string {
  return value.replace(/["\\]/g, '').trim()
}

export interface GraphClientDependencies {
  tokenProvider?: GraphTokenProvider
  fetchImpl?: typeof fetch
  sleepImpl?: (ms: number) => Promise<void>
  maxRetries?: number
  baseBackoffMs?: number
}

const defaultSleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms))

export class MicrosoftGraphClient {
  private readonly tokenProvider: GraphTokenProvider
  private readonly fetchImpl: typeof fetch
  private readonly sleepImpl: (ms: number) => Promise<void>
  private readonly maxRetriesOverride?: number
  private readonly baseBackoffOverride?: number

  constructor(deps: GraphClientDependencies = {}) {
    this.tokenProvider = deps.tokenProvider ?? getGraphTokenProvider()
    this.fetchImpl = deps.fetchImpl ?? fetch
    this.sleepImpl = deps.sleepImpl ?? defaultSleep
    this.maxRetriesOverride = deps.maxRetries
    this.baseBackoffOverride = deps.baseBackoffMs
  }

  public async request<T>(
    pathOrUrl: string,
    options: {
      method?: string
      body?: unknown
      headers?: Record<string, string>
    } = {},
  ): Promise<T> {
    const cfg = getConfig()
    const maxRetries = this.maxRetriesOverride ?? cfg.graphMaxRetries
    const baseBackoffMs = this.baseBackoffOverride ?? cfg.graphBaseBackoffMs

    const url = pathOrUrl.startsWith('https://')
      ? pathOrUrl
      : `${GRAPH_BASE_URL}${pathOrUrl.startsWith('/') ? pathOrUrl : `/${pathOrUrl}`}`

    let refreshedOn401 = false

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const token = await this.tokenProvider.getAccessToken(refreshedOn401)
      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        ...options.headers,
      }
      if (options.body !== undefined) {
        headers['Content-Type'] = 'application/json'
      }

      let response: Response
      try {
        response = await this.fetchImpl(url, {
          method: options.method ?? 'GET',
          headers,
          body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        })
      } catch (networkErr) {
        if (attempt < maxRetries) {
          const delay = computeBackoffMs(attempt, baseBackoffMs, null)
          await this.sleepImpl(delay)
          continue
        }
        throw new GraphApiError(
          0,
          'NETWORK_ERROR',
          networkErr instanceof Error
            ? networkErr.message
            : 'Failed to reach Microsoft Graph API',
        )
      }

      if (response.status === 401 && !refreshedOn401) {
        refreshedOn401 = true
        this.tokenProvider.invalidate()
        continue
      }

      if (RETRYABLE_STATUSES.has(response.status) && attempt < maxRetries) {
        const delay = computeBackoffMs(
          attempt,
          baseBackoffMs,
          response.headers.get('retry-after'),
        )
        await this.sleepImpl(delay)
        continue
      }

      if (response.status === 204) {
        return undefined as T
      }

      const rawText = await response.text()
      const parsed = rawText
        ? (JSON.parse(rawText) as Record<string, unknown>)
        : {}

      if (!response.ok) {
        const errorObj = (parsed.error ?? {}) as {
          code?: string
          message?: string
          innerError?: { 'request-id'?: string }
        }
        throw new GraphApiError(
          response.status,
          errorObj.code || `HTTP_${response.status}`,
          errorObj.message || `Microsoft Graph error (${response.status})`,
          errorObj.innerError?.['request-id'] ??
            response.headers.get('request-id') ??
            undefined,
        )
      }

      return parsed as T
    }

    throw new GraphApiError(
      429,
      'MAX_RETRIES_EXCEEDED',
      'Microsoft Graph request exceeded maximum retry attempts.',
    )
  }

  public async getOrganization(): Promise<GraphOrganization | null> {
    const res = await this.request<{ value: GraphOrganization[] }>(
      '/organization?$select=id,displayName,verifiedDomains',
    )
    return res.value[0] ?? null
  }

  public async listSubscribedSkus(): Promise<GraphSubscribedSku[]> {
    const res = await this.request<{ value: GraphSubscribedSku[] }>(
      '/subscribedSkus?$select=id,skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits',
    )
    return res.value ?? []
  }

  public async listUsers(params: {
    search?: string
    top?: number
    nextLink?: string
  } = {}): Promise<GraphPageResult<GraphUser>> {
    if (params.nextLink) {
      if (!params.nextLink.startsWith('https://graph.microsoft.com/')) {
        throw new GraphApiError(400, 'INVALID_NEXT_LINK', 'Invalid pagination link.')
      }
      const res = await this.request<{
        value: GraphUser[]
        '@odata.nextLink'?: string
      }>(params.nextLink, {
        headers: { ConsistencyLevel: 'eventual' },
      })
      return {
        items: res.value ?? [],
        nextLink: res['@odata.nextLink'] ?? null,
      }
    }

    const top = Math.min(Math.max(params.top ?? 25, 1), 100)
    const select =
      'id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,officeLocation,createdDateTime,assignedLicenses'
    const query = new URLSearchParams({
      $select: select,
      $top: String(top),
    })

    const headers: Record<string, string> = {}
    const cleanedSearch = params.search ? escapeGraphSearch(params.search) : ''

    if (cleanedSearch) {
      query.set(
        '$search',
        `"displayName:${cleanedSearch}" OR "userPrincipalName:${cleanedSearch}" OR "mail:${cleanedSearch}"`,
      )
      query.set('$count', 'true')
      headers.ConsistencyLevel = 'eventual'
    } else {
      query.set('$orderby', 'displayName')
    }

    const res = await this.request<{
      value: GraphUser[]
      '@odata.nextLink'?: string
    }>(`/users?${query.toString()}`, { headers })

    return {
      items: res.value ?? [],
      nextLink: res['@odata.nextLink'] ?? null,
    }
  }

  public async getUser(userId: string): Promise<GraphUser> {
    const select =
      'id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,officeLocation,createdDateTime,assignedLicenses'
    return this.request<GraphUser>(
      `/users/${encodeURIComponent(userId)}?$select=${select}`,
    )
  }

  public async setUserAccountEnabled(
    userId: string,
    accountEnabled: boolean,
  ): Promise<void> {
    await this.request<void>(`/users/${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: { accountEnabled },
    })
  }

  public async assignUserLicenses(
    userId: string,
    addSkuIds: string[],
    removeSkuIds: string[],
  ): Promise<GraphUser> {
    return this.request<GraphUser>(
      `/users/${encodeURIComponent(userId)}/assignLicense`,
      {
        method: 'POST',
        body: {
          addLicenses: addSkuIds.map((skuId) => ({
            skuId,
            disabledPlans: [],
          })),
          removeLicenses: removeSkuIds,
        },
      },
    )
  }

  public async listGroups(params: {
    search?: string
    top?: number
    nextLink?: string
  } = {}): Promise<GraphPageResult<GraphGroup>> {
    if (params.nextLink) {
      if (!params.nextLink.startsWith('https://graph.microsoft.com/')) {
        throw new GraphApiError(400, 'INVALID_NEXT_LINK', 'Invalid pagination link.')
      }
      const res = await this.request<{
        value: GraphGroup[]
        '@odata.nextLink'?: string
      }>(params.nextLink, {
        headers: { ConsistencyLevel: 'eventual' },
      })
      return {
        items: res.value ?? [],
        nextLink: res['@odata.nextLink'] ?? null,
      }
    }

    const top = Math.min(Math.max(params.top ?? 25, 1), 100)
    const select =
      'id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,createdDateTime'
    const query = new URLSearchParams({
      $select: select,
      $top: String(top),
    })

    const headers: Record<string, string> = {}
    const cleanedSearch = params.search ? escapeGraphSearch(params.search) : ''

    if (cleanedSearch) {
      query.set('$search', `"displayName:${cleanedSearch}" OR "mail:${cleanedSearch}"`)
      query.set('$count', 'true')
      headers.ConsistencyLevel = 'eventual'
    } else {
      query.set('$orderby', 'displayName')
    }

    const res = await this.request<{
      value: GraphGroup[]
      '@odata.nextLink'?: string
    }>(`/groups?${query.toString()}`, { headers })

    return {
      items: res.value ?? [],
      nextLink: res['@odata.nextLink'] ?? null,
    }
  }

  public async getGroup(groupId: string): Promise<GraphGroup> {
    const select =
      'id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,createdDateTime'
    return this.request<GraphGroup>(
      `/groups/${encodeURIComponent(groupId)}?$select=${select}`,
    )
  }

  public async listGroupMembers(groupId: string): Promise<GraphGroupMember[]> {
    const res = await this.request<{ value: GraphGroupMember[] }>(
      `/groups/${encodeURIComponent(groupId)}/members?$select=id,displayName,userPrincipalName,mail&$top=100`,
    )
    return res.value ?? []
  }

  public async addGroupMember(groupId: string, userId: string): Promise<void> {
    await this.request<void>(
      `/groups/${encodeURIComponent(groupId)}/members/$ref`,
      {
        method: 'POST',
        body: {
          '@odata.id': `${GRAPH_BASE_URL}/directoryObjects/${encodeURIComponent(userId)}`,
        },
      },
    )
  }

  public async removeGroupMember(groupId: string, memberId: string): Promise<void> {
    await this.request<void>(
      `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}/$ref`,
      {
        method: 'DELETE',
      },
    )
  }

  public async getUserMemberGroupIds(userId: string): Promise<string[]> {
    const res = await this.request<{ value: string[] }>(
      `/users/${encodeURIComponent(userId)}/getMemberGroups`,
      {
        method: 'POST',
        body: { securityEnabledOnly: false },
      },
    )
    return res.value ?? []
  }

  public async findUserByUpn(upn: string): Promise<GraphUser | null> {
    const escaped = escapeODataString(upn.trim())
    const res = await this.request<{ value: GraphUser[] }>(
      `/users?$filter=userPrincipalName eq '${escaped}'&$select=id,displayName,userPrincipalName,mail,accountEnabled,jobTitle,department,officeLocation,assignedLicenses&$top=1`,
    )
    return res.value[0] ?? null
  }

  public async getGrantedRoles(): Promise<string[]> {
    const token = await this.tokenProvider.getAccessToken()
    const parts = token.split('.')
    if (parts.length < 2 || !parts[1]) return []
    try {
      const parsed = JSON.parse(
        Buffer.from(parts[1], 'base64url').toString('utf8'),
      ) as { roles?: unknown }
      if (!Array.isArray(parsed.roles)) return []
      return parsed.roles
        .filter((r): r is string => typeof r === 'string')
        .sort()
    } catch {
      return []
    }
  }

  public async listSignInLogs(
    params: ListSignInLogsParams = {},
  ): Promise<GraphPageResult<GraphSignIn>> {
    if (params.nextLink) {
      if (!params.nextLink.startsWith('https://graph.microsoft.com/')) {
        throw new GraphApiError(
          400,
          'INVALID_NEXT_LINK',
          'Invalid pagination link.',
        )
      }
      const res = await this.request<{
        value: GraphSignIn[]
        '@odata.nextLink'?: string
      }>(params.nextLink)
      return {
        items: res.value ?? [],
        nextLink: res['@odata.nextLink'] ?? null,
      }
    }

    const top = Math.min(Math.max(params.top ?? 50, 1), 200)
    const filters: string[] = []

    if (params.daysBack && params.daysBack > 0) {
      const since = new Date(
        Date.now() - params.daysBack * 24 * 60 * 60 * 1000,
      ).toISOString()
      filters.push(`createdDateTime ge ${since}`)
    }

    if (params.errorCode !== undefined && Number.isFinite(params.errorCode)) {
      filters.push(`status/errorCode eq ${Math.trunc(params.errorCode)}`)
    } else if (params.status === 'failure') {
      filters.push('status/errorCode ne 0')
    } else if (params.status === 'success') {
      filters.push('status/errorCode eq 0')
    } else if (params.status === 'mfa') {
      filters.push(
        '(status/errorCode eq 50074 or status/errorCode eq 50076 or status/errorCode eq 50079 or status/errorCode eq 500121 or status/errorCode eq 50158 or status/errorCode eq 53004)',
      )
    } else if (params.status === 'blocked') {
      filters.push(
        "(conditionalAccessStatus eq 'failure' or status/errorCode eq 53003 or status/errorCode eq 530032 or status/errorCode eq 50053 or status/errorCode eq 50057)",
      )
    }

    if (params.user?.trim()) {
      const escaped = escapeODataString(params.user.trim())
      if (escaped.includes('@')) {
        filters.push(`userPrincipalName eq '${escaped}'`)
      } else {
        filters.push(
          `(startswith(userPrincipalName,'${escaped}') or startswith(userDisplayName,'${escaped}'))`,
        )
      }
    }

    if (params.app?.trim()) {
      const escaped = escapeODataString(params.app.trim())
      filters.push(`startswith(appDisplayName,'${escaped}')`)
    }

    if (params.ipAddress?.trim()) {
      const escaped = escapeODataString(params.ipAddress.trim())
      filters.push(`ipAddress eq '${escaped}'`)
    }

    const query = new URLSearchParams({
      $top: String(top),
      $orderby: 'createdDateTime desc',
    })
    if (filters.length > 0) {
      query.set('$filter', filters.join(' and '))
    }

    const res = await this.request<{
      value: GraphSignIn[]
      '@odata.nextLink'?: string
    }>(`/auditLogs/signIns?${query.toString()}`)

    return {
      items: res.value ?? [],
      nextLink: res['@odata.nextLink'] ?? null,
    }
  }

  public async listUserSignInLogs(
    userIdOrUpn: string,
    top = 15,
  ): Promise<GraphSignIn[]> {
    const trimmed = userIdOrUpn.trim()
    const escaped = escapeODataString(trimmed)
    const isUuid =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        trimmed,
      )
    const filter = isUuid
      ? `userId eq '${escaped}'`
      : `userPrincipalName eq '${escaped}'`
    const query = new URLSearchParams({
      $filter: filter,
      $top: String(Math.min(Math.max(top, 1), 50)),
      $orderby: 'createdDateTime desc',
    })
    const res = await this.request<{ value: GraphSignIn[] }>(
      `/auditLogs/signIns?${query.toString()}`,
    )
    return res.value ?? []
  }
}

let defaultClient: MicrosoftGraphClient | null = null

export function getGraphClient(): MicrosoftGraphClient {
  if (!defaultClient) {
    defaultClient = new MicrosoftGraphClient()
  }
  return defaultClient
}
