export type SignInErrorCategory =
  | 'success'
  | 'credentials'
  | 'mfa'
  | 'conditional_access'
  | 'account_state'
  | 'app_consent'
  | 'device'
  | 'session'
  | 'other'

export interface SignInErrorDiagnosis {
  code: number
  aadstsCode: string
  category: SignInErrorCategory
  title: string
  remediation: string
}

const KNOWN_ERRORS: Record<number, Omit<SignInErrorDiagnosis, 'code' | 'aadstsCode'>> = {
  0: {
    category: 'success',
    title: 'Sign-in succeeded',
    remediation: 'No action required.',
  },
  50053: {
    category: 'account_state',
    title: 'Account locked (Smart Lockout)',
    remediation:
      'Too many failed sign-in attempts triggered Entra Smart Lockout. Wait for the lockout window to expire (typically 1-60 min), check for password spray or cached old credentials on mobile/Outlook, or reset the password if compromised.',
  },
  50055: {
    category: 'credentials',
    title: 'Password expired',
    remediation:
      'Have the user change their password via web sign-in (portal.office.com) or reset their password and require change at next sign-in.',
  },
  50056: {
    category: 'credentials',
    title: 'Invalid or missing password',
    remediation:
      'The user account has no valid password set or submitted an empty credential. Reset the password in Entra ID or verify federation/PTA sync.',
  },
  50057: {
    category: 'account_state',
    title: 'User account is disabled',
    remediation:
      'Re-enable the user account on the Users page if access should be restored, or ignore if this is an offboarded user whose old device is still retrying.',
  },
  50074: {
    category: 'mfa',
    title: 'Strong authentication (MFA) required',
    remediation:
      'Normal interactive MFA challenge step. If followed immediately by a success event, the user completed MFA; if not, the user abandoned or never received the prompt.',
  },
  50076: {
    category: 'mfa',
    title: 'MFA required due to policy or location change',
    remediation:
      'User must complete MFA interactively. If a legacy client or script hit this, switch the app to modern auth or check MFA registration.',
  },
  50079: {
    category: 'mfa',
    title: 'User must enroll in MFA (Security Defaults / policy)',
    remediation:
      'User has not finished registering Microsoft Authenticator / MFA. Have them sign in at https://aka.ms/mfasetup or issue a Temporary Access Pass.',
  },
  500121: {
    category: 'mfa',
    title: 'MFA verification failed, denied, or timed out',
    remediation:
      'Check whether the user tapped Deny (possible credential theft!), missed the Authenticator notification, or has an out-of-sync phone/Authenticator app. Reset MFA methods if they changed phones.',
  },
  50126: {
    category: 'credentials',
    title: 'Invalid username or password',
    remediation:
      'User entered the wrong password or an app has stale cached credentials. Verify caps lock/keyboard layout, clear Windows Credential Manager/Outlook profiles, or reset password.',
  },
  50131: {
    category: 'conditional_access',
    title: 'Sign-in blocked by risk or Conditional Access',
    remediation:
      'Inspect the applied Conditional Access policies and risk signals below to see which rule blocked sign-in.',
  },
  50133: {
    category: 'session',
    title: 'Session invalid due to password change or revocation',
    remediation:
      'Expected after a password reset or session revocation. Have the user sign back in interactively.',
  },
  50140: {
    category: 'session',
    title: 'Keep Me Signed In (KMSI) interrupt',
    remediation:
      'Transient prompt asking whether to stay signed in. Usually followed by a success sign-in; not an actual error.',
  },
  50144: {
    category: 'credentials',
    title: 'On-premises AD password expired',
    remediation:
      'User must update their on-premises Active Directory password (or via SSPR writeback if enabled).',
  },
  50158: {
    category: 'mfa',
    title: 'External security challenge not satisfied',
    remediation:
      'An external MFA provider (e.g., Duo) or custom control interrupted sign-in. Check whether the user completed the external prompt.',
  },
  50105: {
    category: 'app_consent',
    title: 'User not assigned to enterprise application',
    remediation:
      'The app requires user assignment. Assign the user or their security group under Entra ID → Enterprise applications → Users and groups.',
  },
  50020: {
    category: 'account_state',
    title: 'User account does not exist in tenant',
    remediation:
      'User tried to sign into the wrong tenant or has not been invited as a B2B guest. Invite the guest or verify they selected their work account.',
  },
  50034: {
    category: 'account_state',
    title: 'User account not found',
    remediation:
      'Verify the exact UPN spelling or check whether the user was soft-deleted.',
  },
  53000: {
    category: 'device',
    title: 'Device is not compliant',
    remediation:
      'Policy requires an Intune-compliant device. Check Intune compliance status (BitLocker, OS version, password policy) and sync the device.',
  },
  53001: {
    category: 'device',
    title: 'Device is not Hybrid Entra / domain joined',
    remediation:
      'Policy requires a Hybrid Entra joined device. Verify device join state via `dsregcmd /status`.',
  },
  53003: {
    category: 'conditional_access',
    title: 'Blocked by Conditional Access policy',
    remediation:
      'Review the Applied Conditional Access Policies list below to identify the exact policy that returned Failure (e.g., geo-block, legacy auth block, or app restriction).',
  },
  530032: {
    category: 'conditional_access',
    title: 'Blocked by Security Defaults',
    remediation:
      'Microsoft Security Defaults blocked legacy authentication (POP/IMAP/SMTP/Basic Auth) or required MFA. Upgrade the mail client to Modern Auth (OAuth2).',
  },
  53004: {
    category: 'mfa',
    title: 'User must complete MFA registration from trusted location',
    remediation:
      'Have the user register MFA from a trusted corporate network or provide a Temporary Access Pass.',
  },
  65001: {
    category: 'app_consent',
    title: 'User or admin has not consented to application',
    remediation:
      'Grant admin consent for the application in Entra ID → Enterprise applications → Permissions if the app is approved.',
  },
  700082: {
    category: 'session',
    title: 'Refresh token expired due to inactivity',
    remediation:
      'Normal timeout after extended inactivity. Have the user re-authenticate.',
  },
  70043: {
    category: 'session',
    title: 'Refresh token failed sign-in frequency check',
    remediation:
      'Policy requires periodic re-authentication. Have the user sign in interactively again.',
  },
  700016: {
    category: 'app_consent',
    title: 'Application not found in tenant directory',
    remediation:
      'The requested client application ID is missing or deleted from the tenant.',
  },
  81012: {
    category: 'mfa',
    title: 'User canceled MFA or authentication flow',
    remediation:
      'The user closed the browser or clicked Cancel before completing authentication.',
  },
  90002: {
    category: 'account_state',
    title: 'Tenant not found',
    remediation:
      'Verify the domain name or tenant ID configured in the client application.',
  },
}

export function diagnoseSignInError(
  errorCode: number,
  failureReason?: string | null,
): SignInErrorDiagnosis {
  const aadstsCode = errorCode === 0 ? 'SUCCESS' : `AADSTS${errorCode}`
  const known = KNOWN_ERRORS[errorCode]
  if (known) {
    return {
      code: errorCode,
      aadstsCode,
      ...known,
    }
  }

  return {
    code: errorCode,
    aadstsCode,
    category: 'other',
    title: failureReason?.trim() || `Sign-in failed (${aadstsCode})`,
    remediation: `Look up ${aadstsCode} in Microsoft Entra error reference (https://login.microsoftonline.com/error?code=${errorCode}) and inspect the Conditional Access and Device details below.`,
  }
}

export interface GraphPermissionRequirement {
  permission: string
  module: string
  access: 'read' | 'write'
  purpose: string
  tierNote?: string
}

export const POCKET365_GRAPH_PERMISSIONS: GraphPermissionRequirement[] = [
  {
    permission: 'User.ReadWrite.All',
    module: 'Users & Licenses',
    access: 'write',
    purpose: 'List/search users, toggle account enabled, assign/remove licenses, offboarding.',
  },
  {
    permission: 'Group.ReadWrite.All',
    module: 'Groups',
    access: 'write',
    purpose: 'List/search groups and add or remove members.',
  },
  {
    permission: 'Organization.Read.All',
    module: 'Dashboard & Licensing',
    access: 'read',
    purpose: 'Read tenant profile and subscribed license SKU counts.',
  },
  {
    permission: 'AuditLog.Read.All',
    module: 'Sign-in & Directory Audits',
    access: 'read',
    purpose: 'Troubleshoot Entra sign-in logs (7 days on Entra Free; 30 days on P1/P2) and directory audit logs.',
  },
  {
    permission: 'Directory.Read.All',
    module: 'Directory & RBAC',
    access: 'read',
    purpose: 'Fallback group lookup on login and tenant directory metadata.',
  },
]

export function decodeJwtRolesClaim(accessToken: string): string[] {
  const parts = accessToken.split('.')
  if (parts.length < 2 || !parts[1]) return []
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8')
    const payload = JSON.parse(json) as { roles?: unknown }
    if (!Array.isArray(payload.roles)) return []
    return payload.roles
      .filter((r): r is string => typeof r === 'string')
      .sort()
  } catch {
    return []
  }
}

export interface FriendlyGraphError {
  kind: 'permission' | 'license' | 'throttled' | 'other'
  title: string
  message: string
  requiredPermissions?: string[]
  licenseHint?: string
}

export function classifyGraphError(
  err: unknown,
  requiredPermissions: string[] = [],
): FriendlyGraphError {
  const rawMessage = err instanceof Error ? err.message : String(err)
  const lower = rawMessage.toLowerCase()

  if (
    lower.includes('premium license') ||
    lower.includes('aad premium') ||
    lower.includes('b2c') ||
    lower.includes('entitlement') ||
    lower.includes('not enabled for this tenant') ||
    lower.includes('authentication_requestfromunsupporteduserrole')
  ) {
    return {
      kind: 'license',
      title: 'Requires higher Entra ID / Microsoft 365 license tier',
      message: rawMessage,
      requiredPermissions,
      licenseHint:
        'Your tenant appears to be on Entra ID Free (M365 Business Basic/Standard). Some audit/security endpoints require Entra ID P1, P2, or Intune.',
    }
  }

  if (
    lower.includes('authorization_requestdenied') ||
    lower.includes('insufficient privileges') ||
    lower.includes('access is denied') ||
    lower.includes('forbidden') ||
    lower.includes('403')
  ) {
    return {
      kind: 'permission',
      title: 'Missing Microsoft Graph Application Permission',
      message: rawMessage,
      requiredPermissions,
    }
  }

  if (lower.includes('429') || lower.includes('too many requests')) {
    return {
      kind: 'throttled',
      title: 'Microsoft Graph Throttled',
      message: rawMessage,
    }
  }

  return {
    kind: 'other',
    title: 'Microsoft Graph Request Failed',
    message: rawMessage,
  }
}
