import { getCurrentSession } from '~/server/auth/guards'
import { getConfig } from '~/server/config'
import {
  getManagedTenantById,
  resolveActiveTenantForSession,
  resolveTenantGraphCredentials,
} from '~/server/tenants/registry'
import {
  getGraphTokenProvider,
  GraphTokenProvider,
  type GraphTokenProvider as GraphTokenProviderType,
} from './auth'

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

export interface GraphAuthMethod {
  id: string
  '@odata.type': string
  displayName?: string | null
  phoneNumber?: string | null
  phoneType?: string | null
  emailAddress?: string | null
  model?: string | null
  deviceTag?: string | null
  createdDateTime?: string | null
  startDateTime?: string | null
  lifetimeInMinutes?: number | null
  isUsableOnce?: boolean | null
  temporaryAccessPass?: string | null
}

export interface GraphUserRegistrationDetail {
  id: string
  userPrincipalName: string
  userDisplayName: string
  userType?: string | null
  isAdmin: boolean
  isSsprRegistered: boolean
  isSsprEnabled: boolean
  isSsprCapable: boolean
  isMfaRegistered: boolean
  isMfaCapable: boolean
  isPasswordlessCapable: boolean
  methodsRegistered: string[]
  userPreferredMethodForSecondaryAuthentication?: string | null
  lastUpdatedDateTime?: string | null
}

export interface GraphDirectoryMembership {
  id: string
  '@odata.type'?: string
  displayName?: string | null
  groupTypes?: string[]
  securityEnabled?: boolean
  mailEnabled?: boolean
}

export interface GraphDirectoryAuditModifiedProperty {
  displayName: string
  oldValue: string | null
  newValue: string | null
}

export interface GraphDirectoryAuditTarget {
  id: string | null
  displayName: string | null
  type: string | null
  userPrincipalName: string | null
  modifiedProperties?: GraphDirectoryAuditModifiedProperty[]
}

export interface GraphDirectoryAudit {
  id: string
  activityDateTime: string
  activityDisplayName: string
  category: string
  loggedByService: string | null
  operationType: string | null
  result: string | null
  resultReason: string | null
  initiatedBy: {
    user?: {
      id?: string
      displayName?: string
      userPrincipalName?: string
      ipAddress?: string
    } | null
    app?: {
      appId?: string
      displayName?: string
      servicePrincipalId?: string
    } | null
  } | null
  targetResources: GraphDirectoryAuditTarget[]
}

export interface GraphDirectoryRoleMember {
  id: string
  '@odata.type'?: string
  displayName?: string | null
  userPrincipalName?: string | null
  accountEnabled?: boolean | null
}

export interface GraphDirectoryRole {
  id: string
  displayName: string
  description: string | null
  roleTemplateId: string | null
  members?: GraphDirectoryRoleMember[]
}

export interface GraphAuthorizationPolicy {
  id: string
  displayName?: string
  allowInvitesFrom?: string
  guestUserRoleId?: string
  blockMsolPowerShell?: boolean | null
  allowEmailVerifiedUsersToJoinOrganization?: boolean
  defaultUserRolePermissions?: {
    allowedToCreateApps?: boolean
    allowedToCreateSecurityGroups?: boolean
    allowedToCreateTenants?: boolean
    allowedToReadBitlockerKeysForOwnedDevice?: boolean
    allowedToReadOtherUsers?: boolean
    permissionGrantPoliciesAssigned?: string[]
  }
}

export interface GraphSecurityDefaultsPolicy {
  id: string
  displayName?: string
  isEnabled: boolean
}

export interface GraphAdminConsentRequestPolicy {
  isEnabled: boolean
  notifyReviewers?: boolean
  remindersEnabled?: boolean
  requestDurationInDays?: number
}

export interface GraphDomain {
  id: string
  isDefault: boolean
  isInitial: boolean
  isVerified: boolean
  passwordValidityPeriodInDays: number | null
  passwordNotificationWindowInDays: number | null
}

export interface GraphAppCredential {
  keyId: string
  displayName?: string | null
  startDateTime?: string | null
  endDateTime?: string | null
  hint?: string | null
}

export interface GraphApplication {
  id: string
  appId: string
  displayName: string
  createdDateTime?: string | null
  signInAudience?: string | null
  passwordCredentials?: GraphAppCredential[]
  keyCredentials?: GraphAppCredential[]
}

export interface GraphOAuth2PermissionGrant {
  id: string
  clientId: string
  consentType: string
  principalId: string | null
  resourceId: string
  scope: string
}

export interface GraphServicePrincipalLite {
  id: string
  appId: string
  displayName: string
}

export interface GraphStaleUserCandidate extends GraphUser {
  userType?: string | null
  signInActivity?: {
    lastSignInDateTime?: string | null
    lastNonInteractiveSignInDateTime?: string | null
  } | null
}

export interface GraphMailboxAutoReplies {
  status: 'disabled' | 'alwaysEnabled' | 'scheduled'
  externalAudience?: 'none' | 'contactsOnly' | 'all'
  internalReplyMessage?: string | null
  externalReplyMessage?: string | null
  scheduledStartDateTime?: { dateTime: string; timeZone: string } | null
  scheduledEndDateTime?: { dateTime: string; timeZone: string } | null
}

export interface GraphMailboxSettings {
  timeZone?: string | null
  language?: { locale?: string; displayName?: string } | null
  automaticRepliesSetting?: GraphMailboxAutoReplies | null
}

export interface GraphInboxRule {
  id: string
  displayName: string
  sequence?: number
  isEnabled: boolean
  hasError?: boolean
  conditions?: Record<string, unknown>
  actions?: {
    forwardTo?: Array<{ emailAddress?: { name?: string; address?: string } }>
    forwardAsAttachmentTo?: Array<{
      emailAddress?: { name?: string; address?: string }
    }>
    redirectTo?: Array<{ emailAddress?: { name?: string; address?: string } }>
    delete?: boolean
    permanentDelete?: boolean
    markAsRead?: boolean
    moveToFolder?: string
    stopProcessingRules?: boolean
  }
}

export interface GraphConditionalAccessPolicy {
  id: string
  displayName: string
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced'
  createdDateTime?: string | null
  modifiedDateTime?: string | null
  conditions?: Record<string, unknown>
  grantControls?: {
    operator?: string
    builtInControls?: string[]
  } | null
  sessionControls?: Record<string, unknown> | null
}

export interface GraphManagedDevice {
  id: string
  deviceName: string | null
  operatingSystem: string | null
  osVersion: string | null
  complianceState: string | null
  userPrincipalName: string | null
  userDisplayName: string | null
  lastSyncDateTime: string | null
  manufacturer: string | null
  model: string | null
  serialNumber: string | null
  azureADDeviceId: string | null
}

export interface GraphBitlockerRecoveryKey {
  id: string
  createdDateTime: string | null
  deviceId: string | null
  volumeType: string | null
  key?: string | null
}

export interface GraphRiskyUser {
  id: string
  userDisplayName: string | null
  userPrincipalName: string | null
  riskLevel: string | null
  riskState: string | null
  riskDetail: string | null
  riskLastUpdatedDateTime: string | null
}

export interface GraphSecureScore {
  id: string
  createdDateTime: string
  currentScore: number
  maxScore: number
  activeUserCount?: number
  licensedUserCount?: number
  controlScores?: Array<{
    controlName: string
    controlCategory: string
    score: number
    description?: string
  }>
}

export interface GraphSecurityAlert {
  id: string
  title: string
  severity: string
  status: string
  category?: string | null
  serviceSource?: string | null
  createdDateTime: string
  lastUpdateDateTime?: string | null
  description?: string | null
}

export interface GraphSharePointSettings {
  sharingCapability?: string
  isLegacyAuthProtocolsEnabled?: boolean
  isResharingByExternalUsersEnabled?: boolean
  isSitesStorageLimitAutomatic?: boolean
  sharingAllowedDomainList?: string[]
  sharingBlockedDomainList?: string[]
  sharingDomainRestrictionMode?: string
  idleSessionSignOut?: {
    isEnabled?: boolean
    warnAfterInSeconds?: number
    signOutAfterInSeconds?: number
  }
}

export interface GraphAuthMethodConfiguration {
  id: string
  '@odata.type'?: string
  state: 'enabled' | 'disabled'
  featureSettings?: {
    displayAppInformationRequiredState?: { state?: string }
    displayLocationInformationRequiredState?: { state?: string }
    numberMatchingRequiredState?: { state?: string }
  }
}

export interface GraphAuthMethodsPolicy {
  id: string
  policyMigrationState?: string
  authenticationMethodConfigurations?: GraphAuthMethodConfiguration[]
}

export interface CreateEntraUserInput {
  displayName: string
  givenName?: string
  surname?: string
  mailNickname: string
  userPrincipalName: string
  password: string
  forceChangePasswordNextSignIn: boolean
  usageLocation: string
  department?: string
  jobTitle?: string
  officeLocation?: string
  accountEnabled?: boolean
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
  tokenProvider?: GraphTokenProviderType
  fetchImpl?: typeof fetch
  sleepImpl?: (ms: number) => Promise<void>
  maxRetries?: number
  baseBackoffMs?: number
}

const defaultSleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms))

export const AUTH_METHOD_SEGMENTS: Record<string, string> = {
  '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod':
    'microsoftAuthenticatorMethods',
  '#microsoft.graph.phoneAuthenticationMethod': 'phoneMethods',
  '#microsoft.graph.fido2AuthenticationMethod': 'fido2Methods',
  '#microsoft.graph.emailAuthenticationMethod': 'emailMethods',
  '#microsoft.graph.softwareOathAuthenticationMethod': 'softwareOathMethods',
  '#microsoft.graph.temporaryAccessPassAuthenticationMethod':
    'temporaryAccessPassMethods',
  '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod':
    'windowsHelloForBusinessMethods',
}

export function resolveAuthMethodSegment(odataType: string): string | null {
  return AUTH_METHOD_SEGMENTS[odataType] ?? null
}

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

  public async revokeUserSignInSessions(userId: string): Promise<boolean> {
    const res = await this.request<{ value?: boolean }>(
      `/users/${encodeURIComponent(userId)}/revokeSignInSessions`,
      { method: 'POST', body: {} },
    )
    return Boolean(res?.value ?? true)
  }

  public async resetUserPassword(
    userId: string,
    newPassword: string,
    forceChangePasswordNextSignIn = true,
  ): Promise<void> {
    await this.request<void>(`/users/${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: {
        passwordProfile: {
          password: newPassword,
          forceChangePasswordNextSignIn,
        },
      },
    })
  }

  public async listUserAuthenticationMethods(
    userId: string,
  ): Promise<GraphAuthMethod[]> {
    const res = await this.request<{ value: GraphAuthMethod[] }>(
      `/users/${encodeURIComponent(userId)}/authentication/methods`,
    )
    return res.value ?? []
  }

  public async deleteUserAuthenticationMethod(
    userId: string,
    odataType: string,
    methodId: string,
  ): Promise<void> {
    const segment = resolveAuthMethodSegment(odataType)
    if (!segment) {
      throw new GraphApiError(
        400,
        'UNSUPPORTED_AUTH_METHOD',
        `Authentication method type "${odataType}" cannot be deleted via Pocket365.`,
      )
    }
    await this.request<void>(
      `/users/${encodeURIComponent(userId)}/authentication/${segment}/${encodeURIComponent(methodId)}`,
      { method: 'DELETE' },
    )
  }

  public async createTemporaryAccessPass(
    userId: string,
    options: { lifetimeInMinutes: number; isUsableOnce: boolean },
  ): Promise<GraphAuthMethod> {
    return this.request<GraphAuthMethod>(
      `/users/${encodeURIComponent(userId)}/authentication/temporaryAccessPassMethods`,
      {
        method: 'POST',
        body: {
          lifetimeInMinutes: options.lifetimeInMinutes,
          isUsableOnce: options.isUsableOnce,
        },
      },
    )
  }

  public async listUserDirectMemberships(
    userId: string,
  ): Promise<GraphDirectoryMembership[]> {
    const res = await this.request<{ value: GraphDirectoryMembership[] }>(
      `/users/${encodeURIComponent(userId)}/memberOf?$select=id,displayName,groupTypes,securityEnabled,mailEnabled&$top=200`,
    )
    return res.value ?? []
  }

  public async clearUserManager(userId: string): Promise<void> {
    await this.request<void>(
      `/users/${encodeURIComponent(userId)}/manager/$ref`,
      { method: 'DELETE' },
    )
  }

  public async listUserRegistrationDetails(params: {
    top?: number
    nextLink?: string
  } = {}): Promise<GraphPageResult<GraphUserRegistrationDetail>> {
    if (params.nextLink) {
      if (!params.nextLink.startsWith('https://graph.microsoft.com/')) {
        throw new GraphApiError(
          400,
          'INVALID_NEXT_LINK',
          'Invalid pagination link.',
        )
      }
      const res = await this.request<{
        value: GraphUserRegistrationDetail[]
        '@odata.nextLink'?: string
      }>(params.nextLink)
      return {
        items: res.value ?? [],
        nextLink: res['@odata.nextLink'] ?? null,
      }
    }

    const top = Math.min(Math.max(params.top ?? 200, 1), 999)
    const res = await this.request<{
      value: GraphUserRegistrationDetail[]
      '@odata.nextLink'?: string
    }>(`/reports/authenticationMethods/userRegistrationDetails?$top=${top}`)

    return {
      items: res.value ?? [],
      nextLink: res['@odata.nextLink'] ?? null,
    }
  }

  public async listDirectoryAudits(params: {
    category?: string
    activity?: string
    daysBack?: number
    top?: number
    nextLink?: string
  } = {}): Promise<GraphPageResult<GraphDirectoryAudit>> {
    if (params.nextLink) {
      if (!params.nextLink.startsWith('https://graph.microsoft.com/')) {
        throw new GraphApiError(
          400,
          'INVALID_NEXT_LINK',
          'Invalid pagination link.',
        )
      }
      const res = await this.request<{
        value: GraphDirectoryAudit[]
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
      filters.push(`activityDateTime ge ${since}`)
    }
    if (params.category && params.category !== 'all') {
      filters.push(`category eq '${escapeODataString(params.category)}'`)
    }
    if (params.activity?.trim()) {
      filters.push(
        `startswith(activityDisplayName,'${escapeODataString(params.activity.trim())}')`,
      )
    }

    const query = new URLSearchParams({
      $top: String(top),
      $orderby: 'activityDateTime desc',
    })
    if (filters.length > 0) {
      query.set('$filter', filters.join(' and '))
    }

    const res = await this.request<{
      value: GraphDirectoryAudit[]
      '@odata.nextLink'?: string
    }>(`/auditLogs/directoryAudits?${query.toString()}`)

    return {
      items: res.value ?? [],
      nextLink: res['@odata.nextLink'] ?? null,
    }
  }

  public async listDirectoryRolesWithMembers(): Promise<GraphDirectoryRole[]> {
    const res = await this.request<{ value: GraphDirectoryRole[] }>(
      '/directoryRoles?$expand=members($select=id,displayName,userPrincipalName,accountEnabled)',
    )
    return res.value ?? []
  }

  public async addDirectoryRoleMember(
    roleId: string,
    userId: string,
  ): Promise<void> {
    await this.request<void>(
      `/directoryRoles/${encodeURIComponent(roleId)}/members/$ref`,
      {
        method: 'POST',
        body: {
          '@odata.id': `${GRAPH_BASE_URL}/directoryObjects/${encodeURIComponent(userId)}`,
        },
      },
    )
  }

  public async removeDirectoryRoleMember(
    roleId: string,
    memberId: string,
  ): Promise<void> {
    await this.request<void>(
      `/directoryRoles/${encodeURIComponent(roleId)}/members/${encodeURIComponent(memberId)}/$ref`,
      { method: 'DELETE' },
    )
  }

  public async getAuthorizationPolicy(): Promise<GraphAuthorizationPolicy> {
    return this.request<GraphAuthorizationPolicy>(
      '/policies/authorizationPolicy',
    )
  }

  public async updateAuthorizationPolicy(
    patch: Partial<GraphAuthorizationPolicy>,
  ): Promise<void> {
    await this.request<void>('/policies/authorizationPolicy', {
      method: 'PATCH',
      body: patch,
    })
  }

  public async getSecurityDefaultsPolicy(): Promise<GraphSecurityDefaultsPolicy> {
    return this.request<GraphSecurityDefaultsPolicy>(
      '/policies/identitySecurityDefaultsEnforcementPolicy',
    )
  }

  public async setSecurityDefaultsEnabled(isEnabled: boolean): Promise<void> {
    await this.request<void>(
      '/policies/identitySecurityDefaultsEnforcementPolicy',
      {
        method: 'PATCH',
        body: { isEnabled },
      },
    )
  }

  public async getAdminConsentRequestPolicy(): Promise<GraphAdminConsentRequestPolicy> {
    return this.request<GraphAdminConsentRequestPolicy>(
      '/policies/adminConsentRequestPolicy',
    )
  }

  public async setAdminConsentRequestEnabled(
    isEnabled: boolean,
  ): Promise<void> {
    await this.request<void>('/policies/adminConsentRequestPolicy', {
      method: 'PUT',
      body: {
        isEnabled,
        notifyReviewers: true,
        remindersEnabled: true,
        requestDurationInDays: 30,
      },
    })
  }

  public async listDomains(): Promise<GraphDomain[]> {
    const res = await this.request<{ value: GraphDomain[] }>('/domains')
    return res.value ?? []
  }

  public async listConditionalAccessPoliciesSummary(): Promise<
    Array<{ id: string; displayName: string; state: string }>
  > {
    const res = await this.request<{
      value: Array<{ id: string; displayName: string; state: string }>
    }>('/identity/conditionalAccess/policies?$select=id,displayName,state&$top=50')
    return res.value ?? []
  }

  public async listConditionalAccessPoliciesFull(): Promise<
    GraphConditionalAccessPolicy[]
  > {
    const res = await this.request<{ value: GraphConditionalAccessPolicy[] }>(
      '/identity/conditionalAccess/policies?$top=100',
    )
    return res.value ?? []
  }

  public async setConditionalAccessPolicyState(
    policyId: string,
    state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced',
  ): Promise<void> {
    await this.request<void>(
      `/identity/conditionalAccess/policies/${encodeURIComponent(policyId)}`,
      {
        method: 'PATCH',
        body: { state },
      },
    )
  }

  public async listApplications(top = 150): Promise<GraphApplication[]> {
    const res = await this.request<{ value: GraphApplication[] }>(
      `/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$top=${Math.min(Math.max(top, 1), 999)}`,
    )
    return res.value ?? []
  }

  public async listOAuth2PermissionGrants(
    top = 150,
  ): Promise<GraphOAuth2PermissionGrant[]> {
    const res = await this.request<{ value: GraphOAuth2PermissionGrant[] }>(
      `/oauth2PermissionGrants?$top=${Math.min(Math.max(top, 1), 999)}`,
    )
    return res.value ?? []
  }

  public async deleteOAuth2PermissionGrant(grantId: string): Promise<void> {
    await this.request<void>(
      `/oauth2PermissionGrants/${encodeURIComponent(grantId)}`,
      { method: 'DELETE' },
    )
  }

  public async listServicePrincipalsLite(
    top = 300,
  ): Promise<GraphServicePrincipalLite[]> {
    const res = await this.request<{ value: GraphServicePrincipalLite[] }>(
      `/servicePrincipals?$select=id,appId,displayName&$top=${Math.min(Math.max(top, 1), 999)}`,
    )
    return res.value ?? []
  }

  public async listUsersForStaleAudit(top = 250): Promise<{
    users: GraphStaleUserCandidate[]
    hasSignInActivityField: boolean
  }> {
    const clamped = Math.min(Math.max(top, 1), 999)
    try {
      const res = await this.request<{ value: GraphStaleUserCandidate[] }>(
        `/users?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,jobTitle,department,officeLocation,createdDateTime,assignedLicenses,signInActivity&$top=${clamped}`,
      )
      return { users: res.value ?? [], hasSignInActivityField: true }
    } catch (err) {
      if (err instanceof GraphApiError && (err.status === 403 || err.status === 400)) {
        const res = await this.request<{ value: GraphStaleUserCandidate[] }>(
          `/users?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,jobTitle,department,officeLocation,createdDateTime,assignedLicenses&$top=${clamped}`,
        )
        return { users: res.value ?? [], hasSignInActivityField: false }
      }
      throw err
    }
  }

  public async getUserMailboxSettings(
    userId: string,
  ): Promise<GraphMailboxSettings> {
    return this.request<GraphMailboxSettings>(
      `/users/${encodeURIComponent(userId)}/mailboxSettings`,
    )
  }

  public async updateUserAutoReplies(
    userId: string,
    automaticRepliesSetting: GraphMailboxAutoReplies,
  ): Promise<GraphMailboxSettings> {
    return this.request<GraphMailboxSettings>(
      `/users/${encodeURIComponent(userId)}/mailboxSettings`,
      {
        method: 'PATCH',
        body: { automaticRepliesSetting },
      },
    )
  }

  public async listUserInboxRules(userId: string): Promise<GraphInboxRule[]> {
    const res = await this.request<{ value: GraphInboxRule[] }>(
      `/users/${encodeURIComponent(userId)}/mailFolders/inbox/messageRules`,
    )
    return res.value ?? []
  }

  public async deleteUserInboxRule(
    userId: string,
    ruleId: string,
  ): Promise<void> {
    await this.request<void>(
      `/users/${encodeURIComponent(userId)}/mailFolders/inbox/messageRules/${encodeURIComponent(ruleId)}`,
      { method: 'DELETE' },
    )
  }

  public async listManagedDevices(top = 100): Promise<GraphManagedDevice[]> {
    const res = await this.request<{ value: GraphManagedDevice[] }>(
      `/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,userPrincipalName,userDisplayName,lastSyncDateTime,manufacturer,model,serialNumber,azureADDeviceId&$top=${Math.min(Math.max(top, 1), 500)}`,
    )
    return res.value ?? []
  }

  public async syncManagedDevice(deviceId: string): Promise<void> {
    await this.request<void>(
      `/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}/syncDevice`,
      { method: 'POST', body: {} },
    )
  }

  public async remoteLockManagedDevice(deviceId: string): Promise<void> {
    await this.request<void>(
      `/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}/remoteLock`,
      { method: 'POST', body: {} },
    )
  }

  public async listBitlockerRecoveryKeys(
    top = 100,
  ): Promise<GraphBitlockerRecoveryKey[]> {
    const res = await this.request<{ value: GraphBitlockerRecoveryKey[] }>(
      `/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,deviceId,volumeType&$top=${Math.min(Math.max(top, 1), 500)}`,
    )
    return res.value ?? []
  }

  public async getBitlockerRecoveryKeyValue(keyId: string): Promise<string> {
    const res = await this.request<GraphBitlockerRecoveryKey>(
      `/informationProtection/bitlocker/recoveryKeys/${encodeURIComponent(keyId)}?$select=id,key`,
    )
    return res.key ?? ''
  }

  public async listRiskyUsers(top = 100): Promise<GraphRiskyUser[]> {
    const res = await this.request<{ value: GraphRiskyUser[] }>(
      `/identityProtection/riskyUsers?$top=${Math.min(Math.max(top, 1), 500)}`,
    )
    return res.value ?? []
  }

  public async confirmRiskyUserCompromised(userId: string): Promise<void> {
    await this.request<void>('/identityProtection/riskyUsers/confirmCompromised', {
      method: 'POST',
      body: { userIds: [userId] },
    })
  }

  public async dismissRiskyUser(userId: string): Promise<void> {
    await this.request<void>('/identityProtection/riskyUsers/dismiss', {
      method: 'POST',
      body: { userIds: [userId] },
    })
  }

  public async getLatestSecureScore(): Promise<GraphSecureScore | null> {
    const res = await this.request<{ value: GraphSecureScore[] }>(
      '/security/secureScores?$top=1',
    )
    return res.value[0] ?? null
  }

  public async listSecurityAlerts(top = 50): Promise<GraphSecurityAlert[]> {
    const res = await this.request<{ value: GraphSecurityAlert[] }>(
      `/security/alerts_v2?$top=${Math.min(Math.max(top, 1), 200)}&$orderby=createdDateTime desc`,
    )
    return res.value ?? []
  }

  public async getSharePointSettings(): Promise<GraphSharePointSettings> {
    return this.request<GraphSharePointSettings>('/admin/sharepoint/settings')
  }

  public async updateSharePointSettings(
    patch: Partial<GraphSharePointSettings>,
  ): Promise<GraphSharePointSettings> {
    return this.request<GraphSharePointSettings>('/admin/sharepoint/settings', {
      method: 'PATCH',
      body: patch,
    })
  }

  public async getAuthenticationMethodsPolicy(): Promise<GraphAuthMethodsPolicy> {
    return this.request<GraphAuthMethodsPolicy>(
      '/policies/authenticationMethodsPolicy',
    )
  }

  public async setAuthenticationMethodConfigState(
    methodId: 'Sms' | 'Voice' | 'Email',
    state: 'enabled' | 'disabled',
  ): Promise<void> {
    const odataTypeMap = {
      Sms: '#microsoft.graph.smsAuthenticationMethodConfiguration',
      Voice: '#microsoft.graph.voiceAuthenticationMethodConfiguration',
      Email: '#microsoft.graph.emailAuthenticationMethodConfiguration',
    } as const
    await this.request<void>(
      `/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/${methodId}`,
      {
        method: 'PATCH',
        body: {
          '@odata.type': odataTypeMap[methodId],
          state,
        },
      },
    )
  }

  public async createUser(input: CreateEntraUserInput): Promise<GraphUser> {
    return this.request<GraphUser>('/users', {
      method: 'POST',
      body: {
        accountEnabled: input.accountEnabled ?? true,
        displayName: input.displayName,
        givenName: input.givenName || undefined,
        surname: input.surname || undefined,
        mailNickname: input.mailNickname,
        userPrincipalName: input.userPrincipalName,
        usageLocation: input.usageLocation,
        department: input.department || undefined,
        jobTitle: input.jobTitle || undefined,
        officeLocation: input.officeLocation || undefined,
        passwordProfile: {
          password: input.password,
          forceChangePasswordNextSignIn: input.forceChangePasswordNextSignIn,
        },
      },
    })
  }
}

let defaultClient: MicrosoftGraphClient | null = null
const tenantClients = new Map<string, MicrosoftGraphClient>()

export function evictTenantGraphClient(managedTenantId: string): void {
  tenantClients.delete(managedTenantId)
}

export function clearAllTenantGraphClients(): void {
  tenantClients.clear()
  defaultClient = null
}

/**
 * Returns an isolated MicrosoftGraphClient scoped to either:
 * 1) an explicit `managedTenantId`, OR
 * 2) the authenticated session's currently selected tenant (Multi-Tenant Switcher), OR
 * 3) the default primary single-tenant env configuration.
 */
export async function getGraphClient(
  explicitManagedTenantId?: string,
): Promise<MicrosoftGraphClient> {
  let tenantRow = explicitManagedTenantId
    ? await getManagedTenantById(explicitManagedTenantId)
    : null

  if (!tenantRow) {
    try {
      const session = await getCurrentSession()
      if (session?.activeTenantId) {
        tenantRow = await resolveActiveTenantForSession(session)
      }
    } catch {
      tenantRow = null
    }
  }

  if (tenantRow && tenantRow.connectionMode !== 'env_primary') {
    const cached = tenantClients.get(tenantRow.id)
    if (cached) return cached
    const creds = resolveTenantGraphCredentials(tenantRow)
    const provider = new GraphTokenProvider(fetch, creds)
    const client = new MicrosoftGraphClient({ tokenProvider: provider })
    tenantClients.set(tenantRow.id, client)
    return client
  }

  if (!defaultClient) {
    defaultClient = new MicrosoftGraphClient()
  }
  return defaultClient
}
