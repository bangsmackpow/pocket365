import type {
  GraphAuthMethod,
  GraphUserRegistrationDetail,
} from './client'

export interface NormalizedAuthMethod {
  id: string
  odataType: string
  label: string
  detail: string
  deletable: boolean
  createdDateTime: string | null
}

const DELETABLE_AUTH_TYPES = new Set([
  '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
  '#microsoft.graph.phoneAuthenticationMethod',
  '#microsoft.graph.fido2AuthenticationMethod',
  '#microsoft.graph.emailAuthenticationMethod',
  '#microsoft.graph.softwareOathAuthenticationMethod',
  '#microsoft.graph.temporaryAccessPassAuthenticationMethod',
  '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
])

const METHOD_LABELS: Record<string, string> = {
  '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod':
    'Microsoft Authenticator',
  '#microsoft.graph.phoneAuthenticationMethod': 'Phone (SMS / Voice)',
  '#microsoft.graph.fido2AuthenticationMethod': 'FIDO2 Security Key',
  '#microsoft.graph.emailAuthenticationMethod': 'Email OTP',
  '#microsoft.graph.softwareOathAuthenticationMethod': 'Authenticator TOTP App',
  '#microsoft.graph.temporaryAccessPassAuthenticationMethod':
    'Temporary Access Pass (TAP)',
  '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod':
    'Windows Hello for Business',
  '#microsoft.graph.passwordAuthenticationMethod': 'Password',
}

export function normalizeAuthMethod(m: GraphAuthMethod): NormalizedAuthMethod {
  const odataType = m['@odata.type']
  const label =
    METHOD_LABELS[odataType] ??
    odataType
      .replace('#microsoft.graph.', '')
      .replace('AuthenticationMethod', '')

  const detail =
    m.displayName ||
    m.phoneNumber ||
    m.emailAddress ||
    m.model ||
    (m.lifetimeInMinutes
      ? `${m.lifetimeInMinutes}m${m.isUsableOnce ? ' (single-use)' : ''}`
      : '') ||
    m.id

  return {
    id: m.id,
    odataType,
    label,
    detail,
    deletable: DELETABLE_AUTH_TYPES.has(odataType),
    createdDateTime: m.createdDateTime ?? m.startDateTime ?? null,
  }
}

const WEAK_METHODS = new Set([
  'mobilePhone',
  'alternateMobilePhone',
  'officePhone',
  'email',
  'securityQuestion',
])

const STRONG_METHODS = new Set([
  'microsoftAuthenticatorPush',
  'microsoftAuthenticatorPasswordless',
  'fido2SecurityKey',
  'windowsHelloForBusiness',
  'softwareOneTimePasscode',
  'hardwareOneTimePasscode',
  'macOsSecureEnclaveKey',
  'passKeyDeviceBound',
  'passKeyDeviceBoundAuthenticator',
  'passKeyDeviceBoundWindowsHello',
])

export function isWeakMfaOnly(detail: GraphUserRegistrationDetail): boolean {
  if (!detail.isMfaRegistered || detail.methodsRegistered.length === 0) {
    return false
  }
  const hasStrong = detail.methodsRegistered.some((m) => STRONG_METHODS.has(m))
  const hasWeak = detail.methodsRegistered.some((m) => WEAK_METHODS.has(m))
  return hasWeak && !hasStrong
}

export function summarizeMfaCoverage(users: GraphUserRegistrationDetail[]) {
  const total = users.length
  const mfaRegistered = users.filter((u) => u.isMfaRegistered).length
  const mfaMissing = total - mfaRegistered
  const passwordlessCapable = users.filter((u) => u.isPasswordlessCapable).length
  const adminsTotal = users.filter((u) => u.isAdmin).length
  const adminsMissingMfa = users.filter(
    (u) => u.isAdmin && !u.isMfaRegistered,
  ).length
  const weakMfaOnly = users.filter(isWeakMfaOnly).length

  return {
    total,
    mfaRegistered,
    mfaMissing,
    mfaCoveragePct: total > 0 ? Math.round((mfaRegistered / total) * 100) : 0,
    passwordlessCapable,
    passwordlessPct:
      total > 0 ? Math.round((passwordlessCapable / total) * 100) : 0,
    adminsTotal,
    adminsMissingMfa,
    weakMfaOnly,
  }
}

export function synthesizeUserRegistrationDetail(
  user: {
    id: string
    userPrincipalName: string
    displayName?: string | null
    userType?: string | null
  },
  methods: GraphAuthMethod[],
  isAdmin = false,
): GraphUserRegistrationDetail {
  const methodsRegistered: string[] = []
  let isMfaRegistered = false
  let isPasswordlessCapable = false

  for (const m of methods) {
    const t = m['@odata.type'] || ''
    if (t.includes('microsoftAuthenticator')) {
      methodsRegistered.push('microsoftAuthenticatorPush')
      isMfaRegistered = true
    } else if (t.includes('phoneAuthenticationMethod')) {
      methodsRegistered.push('mobilePhone')
      isMfaRegistered = true
    } else if (t.includes('fido2')) {
      methodsRegistered.push('fido2SecurityKey')
      isMfaRegistered = true
      isPasswordlessCapable = true
    } else if (t.includes('softwareOath')) {
      methodsRegistered.push('softwareOneTimePasscode')
      isMfaRegistered = true
    } else if (t.includes('windowsHello')) {
      methodsRegistered.push('windowsHelloForBusiness')
      isMfaRegistered = true
      isPasswordlessCapable = true
    } else if (t.includes('emailAuthenticationMethod')) {
      methodsRegistered.push('email')
    }
  }

  return {
    id: user.id,
    userPrincipalName: user.userPrincipalName,
    userDisplayName: user.displayName || user.userPrincipalName,
    userType: user.userType ?? 'Member',
    isAdmin,
    isSsprRegistered: isMfaRegistered,
    isSsprEnabled: isMfaRegistered,
    isSsprCapable: isMfaRegistered,
    isMfaRegistered,
    isMfaCapable: isMfaRegistered,
    isPasswordlessCapable,
    methodsRegistered,
    userPreferredMethodForSecondaryAuthentication: methodsRegistered[0] ?? null,
    lastUpdatedDateTime: new Date().toISOString(),
  }
}
