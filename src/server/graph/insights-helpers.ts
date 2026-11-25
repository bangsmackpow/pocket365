import type {
  GraphApplication,
  GraphConditionalAccessPolicy,
  GraphInboxRule,
  GraphOAuth2PermissionGrant,
  GraphStaleUserCandidate,
} from './client'

export type CredentialExpiryState = 'expired' | 'critical' | 'warning' | 'healthy'

export interface AppCredentialFinding {
  appObjectId: string
  appId: string
  appDisplayName: string
  credentialType: 'secret' | 'certificate'
  keyId: string
  credentialName: string
  endDateTime: string | null
  daysRemaining: number | null
  state: CredentialExpiryState
}

const MS_PER_DAY = 24 * 60 * 60 * 1000

export function analyzeAppCredentials(
  apps: GraphApplication[],
  nowMs = Date.now(),
): AppCredentialFinding[] {
  const findings: AppCredentialFinding[] = []

  const pushCred = (
    app: GraphApplication,
    credentialType: 'secret' | 'certificate',
    cred: {
      keyId: string
      displayName?: string | null
      endDateTime?: string | null
      hint?: string | null
    },
  ) => {
    const endMs = cred.endDateTime ? Date.parse(cred.endDateTime) : Number.NaN
    const daysRemaining = Number.isFinite(endMs)
      ? Math.floor((endMs - nowMs) / MS_PER_DAY)
      : null

    let state: CredentialExpiryState = 'healthy'
    if (daysRemaining !== null) {
      if (daysRemaining < 0) state = 'expired'
      else if (daysRemaining <= 30) state = 'critical'
      else if (daysRemaining <= 60) state = 'warning'
    }

    findings.push({
      appObjectId: app.id,
      appId: app.appId,
      appDisplayName: app.displayName,
      credentialType,
      keyId: cred.keyId,
      credentialName:
        cred.displayName || (cred.hint ? `Secret (${cred.hint}...)` : cred.keyId.slice(0, 8)),
      endDateTime: cred.endDateTime ?? null,
      daysRemaining,
      state,
    })
  }

  for (const app of apps) {
    for (const secret of app.passwordCredentials ?? []) {
      pushCred(app, 'secret', secret)
    }
    for (const cert of app.keyCredentials ?? []) {
      pushCred(app, 'certificate', cert)
    }
  }

  return findings.sort((a, b) => {
    const da = a.daysRemaining ?? 99999
    const db = b.daysRemaining ?? 99999
    return da - db
  })
}

const HIGH_RISK_SCOPES = new Set([
  'mail.read',
  'mail.readwrite',
  'mail.send',
  'files.read.all',
  'files.readwrite.all',
  'sites.readwrite.all',
  'directory.readwrite.all',
  'directory.accessasuser.all',
  'user.readwrite.all',
  'rolemanagement.readwrite.directory',
  'application.readwrite.all',
  'full_access_as_app',
  'ews.accessasuser.all',
])

export interface AnalyzedOAuthGrant {
  id: string
  clientId: string
  clientDisplayName: string
  resourceDisplayName: string
  consentType: string
  principalId: string | null
  scopes: string[]
  riskyScopes: string[]
  isHighRisk: boolean
}

export function analyzeOAuthGrants(
  grants: GraphOAuth2PermissionGrant[],
  spMap: Map<string, string>,
): AnalyzedOAuthGrant[] {
  return grants
    .map((g) => {
      const scopes = g.scope
        .split(/\s+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const riskyScopes = scopes.filter((s) =>
        HIGH_RISK_SCOPES.has(s.toLowerCase()),
      )
      return {
        id: g.id,
        clientId: g.clientId,
        clientDisplayName: spMap.get(g.clientId) ?? g.clientId,
        resourceDisplayName: spMap.get(g.resourceId) ?? g.resourceId,
        consentType: g.consentType,
        principalId: g.principalId,
        scopes,
        riskyScopes,
        isHighRisk: riskyScopes.length > 0,
      }
    })
    .sort((a, b) => Number(b.isHighRisk) - Number(a.isHighRisk))
}

export interface InboxRuleRiskAnalysis {
  id: string
  displayName: string
  isEnabled: boolean
  hasError: boolean
  riskLevel: 'high' | 'medium' | 'low'
  riskReasons: string[]
  forwardTargets: string[]
  actionsSummary: string[]
}

export function analyzeInboxRuleRisk(rule: GraphInboxRule): InboxRuleRiskAnalysis {
  const actions = rule.actions ?? {}
  const riskReasons: string[] = []
  const forwardTargets: string[] = []
  const actionsSummary: string[] = []

  const extractAddresses = (
    list?: Array<{ emailAddress?: { name?: string; address?: string } }>,
  ) =>
    (list ?? [])
      .map((item) => item.emailAddress?.address || item.emailAddress?.name)
      .filter((v): v is string => Boolean(v))

  const fwd = extractAddresses(actions.forwardTo)
  const fwdAtt = extractAddresses(actions.forwardAsAttachmentTo)
  const redir = extractAddresses(actions.redirectTo)

  if (fwd.length > 0) {
    forwardTargets.push(...fwd)
    actionsSummary.push(`Forward to ${fwd.join(', ')}`)
    riskReasons.push('Automatically forwards incoming emails (BEC exfiltration indicator)')
  }
  if (fwdAtt.length > 0) {
    forwardTargets.push(...fwdAtt)
    actionsSummary.push(`Forward as attachment to ${fwdAtt.join(', ')}`)
    riskReasons.push('Forwards emails as attachments')
  }
  if (redir.length > 0) {
    forwardTargets.push(...redir)
    actionsSummary.push(`Redirect to ${redir.join(', ')}`)
    riskReasons.push('Silently redirects incoming emails')
  }
  if (actions.permanentDelete) {
    actionsSummary.push('Permanently delete')
    riskReasons.push('Permanently deletes matching messages')
  } else if (actions.delete) {
    actionsSummary.push('Delete')
    if (actions.markAsRead) {
      riskReasons.push('Deletes and marks messages read (stealth hiding indicator)')
    }
  }
  if (actions.markAsRead) {
    actionsSummary.push('Mark as read')
  }
  if (actions.moveToFolder) {
    actionsSummary.push(`Move to folder (${actions.moveToFolder})`)
  }

  let riskLevel: 'high' | 'medium' | 'low' = 'low'
  if (forwardTargets.length > 0 || actions.permanentDelete) {
    riskLevel = 'high'
  } else if (actions.delete && actions.markAsRead) {
    riskLevel = 'medium'
  }

  return {
    id: rule.id,
    displayName: rule.displayName,
    isEnabled: rule.isEnabled,
    hasError: Boolean(rule.hasError),
    riskLevel,
    riskReasons,
    forwardTargets,
    actionsSummary:
      actionsSummary.length > 0 ? actionsSummary : ['No forwarding/deletion actions'],
  }
}

export interface CaDriftItem {
  policyId: string
  displayName: string
  changeType: 'added' | 'removed' | 'modified'
  changes: string[]
}

export interface CaDriftSummary {
  hasDrift: boolean
  added: number
  removed: number
  modified: number
  items: CaDriftItem[]
}

export function diffConditionalAccessSnapshots(
  baseline: GraphConditionalAccessPolicy[],
  current: GraphConditionalAccessPolicy[],
): CaDriftSummary {
  const baseMap = new Map(baseline.map((p) => [p.id, p]))
  const currMap = new Map(current.map((p) => [p.id, p]))
  const items: CaDriftItem[] = []

  for (const policy of current) {
    const prev = baseMap.get(policy.id)
    if (!prev) {
      items.push({
        policyId: policy.id,
        displayName: policy.displayName,
        changeType: 'added',
        changes: [`New policy added (state: ${policy.state})`],
      })
      continue
    }

    const changes: string[] = []
    if (prev.displayName !== policy.displayName) {
      changes.push(`Renamed: "${prev.displayName}" → "${policy.displayName}"`)
    }
    if (prev.state !== policy.state) {
      changes.push(`State changed: ${prev.state} → ${policy.state}`)
    }
    if (
      JSON.stringify(prev.grantControls ?? null) !==
      JSON.stringify(policy.grantControls ?? null)
    ) {
      changes.push('Grant controls modified')
    }
    if (
      JSON.stringify(prev.conditions ?? null) !==
      JSON.stringify(policy.conditions ?? null)
    ) {
      changes.push('Targeting conditions (users/groups/apps/locations) modified')
    }
    if (
      JSON.stringify(prev.sessionControls ?? null) !==
      JSON.stringify(policy.sessionControls ?? null)
    ) {
      changes.push('Session controls modified')
    }

    if (changes.length > 0) {
      items.push({
        policyId: policy.id,
        displayName: policy.displayName,
        changeType: 'modified',
        changes,
      })
    }
  }

  for (const prev of baseline) {
    if (!currMap.has(prev.id)) {
      items.push({
        policyId: prev.id,
        displayName: prev.displayName,
        changeType: 'removed',
        changes: [`Policy removed (was ${prev.state})`],
      })
    }
  }

  const added = items.filter((i) => i.changeType === 'added').length
  const removed = items.filter((i) => i.changeType === 'removed').length
  const modified = items.filter((i) => i.changeType === 'modified').length

  return {
    hasDrift: items.length > 0,
    added,
    removed,
    modified,
    items,
  }
}

export interface StaleAccountRow {
  id: string
  displayName: string
  userPrincipalName: string
  userType: 'Member' | 'Guest'
  accountEnabled: boolean
  licenseCount: number
  assignedSkuIds: string[]
  lastSignInDateTime: string | null
  daysSinceLastSignIn: number | null
  createdDateTime: string | null
  flags: Array<'disabled_with_license' | 'stale_licensed' | 'stale_guest' | 'never_signed_in'>
}

export function classifyStaleAccounts(
  users: GraphStaleUserCandidate[],
  staleThresholdDays: number,
  recentSignInFallbackMap: Map<string, string>,
  nowMs = Date.now(),
): StaleAccountRow[] {
  return users.map((u) => {
    const isGuest =
      u.userType?.toLowerCase() === 'guest' ||
      u.userPrincipalName.includes('#EXT#')
    const accountEnabled = u.accountEnabled !== false
    const licenseCount = u.assignedLicenses?.length ?? 0

    const interactive = u.signInActivity?.lastSignInDateTime ?? null
    const nonInteractive =
      u.signInActivity?.lastNonInteractiveSignInDateTime ?? null
    const fallback =
      recentSignInFallbackMap.get(u.id) ??
      recentSignInFallbackMap.get(u.userPrincipalName.toLowerCase()) ??
      null

    const candidates = [interactive, nonInteractive, fallback]
      .filter((d): d is string => Boolean(d))
      .map((d) => ({ iso: d, ms: Date.parse(d) }))
      .filter((x) => Number.isFinite(x.ms))
      .sort((a, b) => b.ms - a.ms)

    const lastSignInDateTime = candidates[0]?.iso ?? null
    const daysSinceLastSignIn = candidates[0]
      ? Math.floor((nowMs - candidates[0].ms) / MS_PER_DAY)
      : null

    const flags: StaleAccountRow['flags'] = []
    if (!accountEnabled && licenseCount > 0) {
      flags.push('disabled_with_license')
    }
    const isStale =
      daysSinceLastSignIn === null || daysSinceLastSignIn >= staleThresholdDays
    if (isStale && accountEnabled && licenseCount > 0) {
      flags.push('stale_licensed')
    }
    if (isGuest && isStale) {
      flags.push('stale_guest')
    }
    if (daysSinceLastSignIn === null) {
      flags.push('never_signed_in')
    }

    return {
      id: u.id,
      displayName: u.displayName,
      userPrincipalName: u.userPrincipalName,
      userType: isGuest ? 'Guest' : 'Member',
      accountEnabled,
      licenseCount,
      assignedSkuIds: (u.assignedLicenses ?? []).map((l) => l.skuId),
      lastSignInDateTime,
      daysSinceLastSignIn,
      createdDateTime: u.createdDateTime ?? null,
      flags,
    }
  })
}
