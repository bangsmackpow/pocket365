import type {
  GraphAdminConsentRequestPolicy,
  GraphAuthorizationPolicy,
  GraphDirectoryRole,
  GraphDomain,
  GraphSecurityDefaultsPolicy,
  GraphUserRegistrationDetail,
} from './client'
import { isWeakMfaOnly } from './mfa-helpers'

export type CisStatus = 'pass' | 'fail' | 'warn' | 'unavailable'
export type CisSeverity = 'critical' | 'high' | 'medium'
export type CisCategory =
  | 'Identity & MFA'
  | 'Privileged Access'
  | 'Apps & Consent'
  | 'Guests & Collaboration'

export type CisRemediationId =
  | 'enable_security_defaults'
  | 'block_user_app_consent'
  | 'disable_user_app_registration'
  | 'disable_user_tenant_creation'
  | 'disable_user_security_group_creation'
  | 'restrict_guest_access'
  | 'restrict_guest_invites'
  | 'block_msol_powershell'
  | 'enable_admin_consent_workflow'

export interface CisCheckResult {
  id: string
  cisRef: string
  title: string
  category: CisCategory
  severity: CisSeverity
  status: CisStatus
  currentValue: string
  expectedValue: string
  howToResolve: string[]
  remediationId?: CisRemediationId
  remediationLabel?: string
  requiredPermissions: string[]
  linkTo?: string
}

export interface CisTenantSnapshot {
  authorizationPolicy: GraphAuthorizationPolicy | null
  authorizationPolicyError?: string | null
  securityDefaults: GraphSecurityDefaultsPolicy | null
  securityDefaultsError?: string | null
  adminConsentPolicy: GraphAdminConsentRequestPolicy | null
  adminConsentPolicyError?: string | null
  conditionalAccessEnabledCount: number | null
  directoryRoles: GraphDirectoryRole[] | null
  directoryRolesError?: string | null
  mfaRegistrations: GraphUserRegistrationDetail[] | null
  mfaRegistrationsError?: string | null
  domains: GraphDomain[] | null
  domainsError?: string | null
}

export const GUEST_ROLE_IDS = {
  MEMBER_EQUIVALENT: 'a0b1b346-4d3e-4e8b-98f8-753987be4970',
  LIMITED: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
  RESTRICTED: '2af84b1e-32c8-42b7-82bc-daa82404023b',
} as const

const GLOBAL_ADMIN_TEMPLATE_ID = '62e90394-69f5-4237-9190-012177145e10'

export function evaluateCisBenchmarks(
  snapshot: CisTenantSnapshot,
): CisCheckResult[] {
  const checks: CisCheckResult[] = []

  // 1. CIS 5.2.2.1 — Security Defaults OR Conditional Access MFA
  if (snapshot.securityDefaults) {
    const secDefaultsOn = snapshot.securityDefaults.isEnabled
    const hasActiveCa = (snapshot.conditionalAccessEnabledCount ?? 0) > 0
    const pass = secDefaultsOn || hasActiveCa
    checks.push({
      id: 'security_defaults',
      cisRef: 'CIS 5.2.2.1',
      title: 'Enable Security Defaults (or Conditional Access MFA)',
      category: 'Identity & MFA',
      severity: 'critical',
      status: pass ? 'pass' : 'fail',
      currentValue: secDefaultsOn
        ? 'Security Defaults enabled'
        : hasActiveCa
          ? `Security Defaults off (${snapshot.conditionalAccessEnabledCount} active CA policies)`
          : 'Security Defaults disabled & no active Conditional Access policies',
      expectedValue:
        'Security Defaults enabled (recommended on Entra Free / Business Basic & Standard) OR Conditional Access enabled (P1/P2)',
      howToResolve: [
        'Open Microsoft Entra admin center → Identity → Overview → Properties.',
        'Click "Manage security defaults".',
        'Set Security defaults to Enabled and Save.',
      ],
      remediationId: !pass ? 'enable_security_defaults' : undefined,
      remediationLabel: '1-Click: Enable Security Defaults',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.SecurityDefaults'],
    })
  } else {
    checks.push({
      id: 'security_defaults',
      cisRef: 'CIS 5.2.2.1',
      title: 'Enable Security Defaults (or Conditional Access MFA)',
      category: 'Identity & MFA',
      severity: 'critical',
      status: 'unavailable',
      currentValue: snapshot.securityDefaultsError || 'Permission required',
      expectedValue: 'Security Defaults enabled',
      howToResolve: [
        'Grant Microsoft Graph Application permission Policy.Read.All (and Policy.ReadWrite.SecurityDefaults for 1-click fix).',
      ],
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.SecurityDefaults'],
    })
  }

  // 2. CIS 1.1.1 — MFA for ALL Privileged Admins
  if (snapshot.mfaRegistrations) {
    const admins = snapshot.mfaRegistrations.filter((u) => u.isAdmin)
    const adminsNoMfa = admins.filter((u) => !u.isMfaRegistered)
    checks.push({
      id: 'admin_mfa',
      cisRef: 'CIS 1.1.1',
      title: 'Ensure MFA is enabled for all administrative roles',
      category: 'Privileged Access',
      severity: 'critical',
      status: adminsNoMfa.length === 0 ? 'pass' : 'fail',
      currentValue:
        adminsNoMfa.length === 0
          ? `All ${admins.length} privileged admin(s) have MFA registered`
          : `${adminsNoMfa.length} admin(s) missing MFA: ${adminsNoMfa
              .slice(0, 3)
              .map((a) => a.userPrincipalName)
              .join(', ')}${adminsNoMfa.length > 3 ? '...' : ''}`,
      expectedValue: '0 privileged admins without MFA registered',
      howToResolve: [
        'Open Pocket365 → MFA Coverage → filter "Admins Missing MFA".',
        'Require each admin to register Microsoft Authenticator or FIDO2 key at https://aka.ms/mfasetup.',
        'Or issue a Temporary Access Pass (TAP) from Pocket365 to bootstrap passwordless/MFA onboarding.',
      ],
      requiredPermissions: ['UserAuthenticationMethod.ReadWrite.All'],
      linkTo: '/mfa',
    })

    // 3. CIS 1.1.2 — MFA for All Users
    const total = snapshot.mfaRegistrations.length
    const missing = snapshot.mfaRegistrations.filter((u) => !u.isMfaRegistered)
    const weakOnly = snapshot.mfaRegistrations.filter(isWeakMfaOnly)
    const pct = total > 0 ? Math.round(((total - missing.length) / total) * 100) : 100
    checks.push({
      id: 'all_users_mfa',
      cisRef: 'CIS 1.1.2',
      title: 'Ensure MFA is registered for all non-admin users',
      category: 'Identity & MFA',
      severity: 'high',
      status:
        missing.length === 0
          ? weakOnly.length === 0
            ? 'pass'
            : 'warn'
          : 'fail',
      currentValue: `${pct}% registered (${missing.length} missing MFA, ${weakOnly.length} SMS/Voice-only)`,
      expectedValue: '100% of active users registered with strong MFA (Authenticator / FIDO2)',
      howToResolve: [
        'Open Pocket365 → MFA Coverage → filter "Missing MFA" and "Weak MFA (SMS/Voice)".',
        'Enable Security Defaults (CIS 5.2.2.1) so users are prompted to enroll Microsoft Authenticator within 14 days.',
        'Disable or offboard stale accounts that no longer need access.',
      ],
      requiredPermissions: ['UserAuthenticationMethod.ReadWrite.All'],
      linkTo: '/mfa',
    })
  } else {
    const errText = snapshot.mfaRegistrationsError || 'Permission required'
    checks.push(
      {
        id: 'admin_mfa',
        cisRef: 'CIS 1.1.1',
        title: 'Ensure MFA is enabled for all administrative roles',
        category: 'Privileged Access',
        severity: 'critical',
        status: 'unavailable',
        currentValue: errText,
        expectedValue: '0 privileged admins without MFA',
        howToResolve: [
          'Grant UserAuthenticationMethod.ReadWrite.All (and AuditLog.Read.All) to evaluate live MFA registration.',
        ],
        requiredPermissions: ['UserAuthenticationMethod.ReadWrite.All'],
        linkTo: '/mfa',
      },
      {
        id: 'all_users_mfa',
        cisRef: 'CIS 1.1.2',
        title: 'Ensure MFA is registered for all non-admin users',
        category: 'Identity & MFA',
        severity: 'high',
        status: 'unavailable',
        currentValue: errText,
        expectedValue: '100% of users MFA-registered',
        howToResolve: [
          'Grant UserAuthenticationMethod.ReadWrite.All to evaluate tenant MFA coverage.',
        ],
        requiredPermissions: ['UserAuthenticationMethod.ReadWrite.All'],
        linkTo: '/mfa',
      },
    )
  }

  // 4. CIS 1.1.3 — Between 2 and 4 Global Administrators
  if (snapshot.directoryRoles) {
    const globalAdminRole = snapshot.directoryRoles.find(
      (r) =>
        r.roleTemplateId === GLOBAL_ADMIN_TEMPLATE_ID ||
        r.displayName.toLowerCase() === 'global administrator',
    )
    const gaCount = globalAdminRole?.members?.length ?? 0
    const status: CisStatus =
      gaCount >= 2 && gaCount <= 4 ? 'pass' : gaCount < 2 ? 'warn' : 'fail'
    checks.push({
      id: 'global_admin_count',
      cisRef: 'CIS 1.1.3',
      title: 'Maintain between 2 and 4 Global Administrators',
      category: 'Privileged Access',
      severity: 'high',
      status,
      currentValue: `${gaCount} Global Administrator(s) assigned`,
      expectedValue: 'Between 2 and 4 Global Administrators (including break-glass account)',
      howToResolve: [
        'Open Pocket365 → Privileged Roles → Global Administrator.',
        'If fewer than 2: create a dedicated cloud-only emergency break-glass account.',
        'If more than 4: downgrade daily-driver accounts to least-privilege roles (e.g., User Admin, Helpdesk Admin, Exchange Admin).',
      ],
      requiredPermissions: ['RoleManagement.ReadWrite.Directory'],
      linkTo: '/roles',
    })
  } else {
    checks.push({
      id: 'global_admin_count',
      cisRef: 'CIS 1.1.3',
      title: 'Maintain between 2 and 4 Global Administrators',
      category: 'Privileged Access',
      severity: 'high',
      status: 'unavailable',
      currentValue: snapshot.directoryRolesError || 'Permission required',
      expectedValue: '2–4 Global Administrators',
      howToResolve: [
        'Grant Directory.Read.All or RoleManagement.ReadWrite.Directory.',
      ],
      requiredPermissions: ['RoleManagement.ReadWrite.Directory'],
      linkTo: '/roles',
    })
  }

  // Authorization Policy Controls (CIS 5.1.2.x & 5.1.6.2)
  const authPol = snapshot.authorizationPolicy
  const defaultPerms = authPol?.defaultUserRolePermissions

  if (authPol && defaultPerms) {
    // 5. CIS 5.1.2.1 — Restrict user consent to third-party apps
    const grantPolicies = defaultPerms.permissionGrantPoliciesAssigned ?? []
    const allowsLegacyConsent = grantPolicies.some((p) =>
      p.toLowerCase().includes('microsoft-user-default-legacy'),
    )
    const consentRestricted = grantPolicies.length === 0 || !allowsLegacyConsent
    checks.push({
      id: 'user_app_consent',
      cisRef: 'CIS 5.1.2.1',
      title: 'Block unrestricted user consent to third-party applications',
      category: 'Apps & Consent',
      severity: 'critical',
      status: consentRestricted ? 'pass' : 'fail',
      currentValue:
        grantPolicies.length === 0
          ? 'User consent blocked (admin approval required)'
          : grantPolicies.join(', '),
      expectedValue: 'No legacy/unrestricted user consent policy assigned',
      howToResolve: [
        'Open Entra admin center → Identity → Applications → Enterprise applications → Consent and permissions → User consent settings.',
        'Select "Do not allow user consent" (recommended) and pair with Admin Consent Workflow.',
      ],
      remediationId: !consentRestricted ? 'block_user_app_consent' : undefined,
      remediationLabel: '1-Click: Block User App Consent',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 6. CIS 5.1.2.2 — Users cannot register applications
    const canCreateApps = defaultPerms.allowedToCreateApps !== false
    checks.push({
      id: 'user_app_registration',
      cisRef: 'CIS 5.1.2.2',
      title: 'Prevent non-admin users from registering new applications',
      category: 'Apps & Consent',
      severity: 'high',
      status: !canCreateApps ? 'pass' : 'fail',
      currentValue: canCreateApps
        ? 'Users can register apps (allowedToCreateApps = true)'
        : 'Blocked (allowedToCreateApps = false)',
      expectedValue: 'allowedToCreateApps = false',
      howToResolve: [
        'Open Entra admin center → Identity → Users → User settings.',
        'Set "Users can register applications" to No and Save.',
      ],
      remediationId: canCreateApps ? 'disable_user_app_registration' : undefined,
      remediationLabel: '1-Click: Disable User App Registration',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 7. CIS 5.1.2.3 — Users cannot create new Entra tenants
    const canCreateTenants = defaultPerms.allowedToCreateTenants !== false
    checks.push({
      id: 'user_tenant_creation',
      cisRef: 'CIS 5.1.2.3',
      title: 'Restrict non-admin users from creating Entra ID tenants',
      category: 'Apps & Consent',
      severity: 'medium',
      status: !canCreateTenants ? 'pass' : 'fail',
      currentValue: canCreateTenants
        ? 'Allowed (allowedToCreateTenants = true)'
        : 'Restricted (allowedToCreateTenants = false)',
      expectedValue: 'allowedToCreateTenants = false',
      howToResolve: [
        'Open Entra admin center → Identity → Users → User settings.',
        'Set "Restrict non-admin users from creating tenants" to Yes.',
      ],
      remediationId: canCreateTenants ? 'disable_user_tenant_creation' : undefined,
      remediationLabel: '1-Click: Block Tenant Creation',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 8. CIS 5.1.2.4 — Users cannot create security groups
    const canCreateSecGroups = defaultPerms.allowedToCreateSecurityGroups !== false
    checks.push({
      id: 'user_security_groups',
      cisRef: 'CIS 5.1.2.4',
      title: 'Restrict non-admin users from creating security groups',
      category: 'Guests & Collaboration',
      severity: 'medium',
      status: !canCreateSecGroups ? 'pass' : 'fail',
      currentValue: canCreateSecGroups
        ? 'Allowed (allowedToCreateSecurityGroups = true)'
        : 'Restricted (allowedToCreateSecurityGroups = false)',
      expectedValue: 'allowedToCreateSecurityGroups = false',
      howToResolve: [
        'Open Entra admin center → Identity → Groups → Group settings → General.',
        'Set "Users can create security groups in Azure portals, API or PowerShell" to No.',
      ],
      remediationId: canCreateSecGroups
        ? 'disable_user_security_group_creation'
        : undefined,
      remediationLabel: '1-Click: Restrict Security Group Creation',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 9. CIS 5.1.2.5 — Block legacy MSOL PowerShell for non-admins
    const msolBlocked = authPol.blockMsolPowerShell === true
    checks.push({
      id: 'block_msol_powershell',
      cisRef: 'CIS 5.1.2.5',
      title: 'Block legacy MSOL PowerShell access for non-admin users',
      category: 'Privileged Access',
      severity: 'medium',
      status: msolBlocked ? 'pass' : 'fail',
      currentValue: msolBlocked
        ? 'Blocked (blockMsolPowerShell = true)'
        : 'Not blocked (blockMsolPowerShell = false)',
      expectedValue: 'blockMsolPowerShell = true',
      howToResolve: [
        'Prevent standard users from enumerating directory data through legacy MSOnline PowerShell endpoints by setting blockMsolPowerShell to true on authorizationPolicy.',
      ],
      remediationId: !msolBlocked ? 'block_msol_powershell' : undefined,
      remediationLabel: '1-Click: Block MSOL PowerShell',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 10. CIS 5.1.2.6 — Restrict Guest User Access
    const guestRole = (authPol.guestUserRoleId || '').toLowerCase()
    const isRestrictedGuest = guestRole === GUEST_ROLE_IDS.RESTRICTED
    const isLimitedGuest = guestRole === GUEST_ROLE_IDS.LIMITED
    checks.push({
      id: 'guest_access_restriction',
      cisRef: 'CIS 5.1.2.6',
      title: 'Restrict external guest user directory visibility',
      category: 'Guests & Collaboration',
      severity: 'high',
      status: isRestrictedGuest ? 'pass' : isLimitedGuest ? 'warn' : 'fail',
      currentValue: isRestrictedGuest
        ? 'Most restrictive (own directory objects only)'
        : isLimitedGuest
          ? 'Limited (can view some directory properties)'
          : 'Same access as member users (over-permissive!)',
      expectedValue:
        'Guest user access restricted to properties and memberships of their own directory objects',
      howToResolve: [
        'Open Entra admin center → Identity → External Identities → External collaboration settings.',
        'Under Guest user access, choose "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)".',
      ],
      remediationId: !isRestrictedGuest ? 'restrict_guest_access' : undefined,
      remediationLabel: '1-Click: Set Most Restrictive Guest Access',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })

    // 11. CIS 5.1.6.2 — Restrict who can invite external guests
    const inviteMode = authPol.allowInvitesFrom || 'everyone'
    const invitesRestricted =
      inviteMode === 'adminsAndGuestInviters' || inviteMode === 'none'
    checks.push({
      id: 'guest_invite_restriction',
      cisRef: 'CIS 5.1.6.2',
      title: 'Restrict external guest invitations to admins & Guest Inviters',
      category: 'Guests & Collaboration',
      severity: 'medium',
      status: invitesRestricted ? 'pass' : 'fail',
      currentValue: `allowInvitesFrom = ${inviteMode}`,
      expectedValue: 'adminsAndGuestInviters or none',
      howToResolve: [
        'Open Entra admin center → Identity → External Identities → External collaboration settings.',
        'Under Guest invite settings, select "Only users assigned to specific admin roles can invite guest users" (or "No one").',
      ],
      remediationId: !invitesRestricted ? 'restrict_guest_invites' : undefined,
      remediationLabel: '1-Click: Restrict Guest Invites to Admins',
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })
  } else {
    const errText = snapshot.authorizationPolicyError || 'Permission required'
    checks.push({
      id: 'authorization_policy_unavailable',
      cisRef: 'CIS 5.1.2.x',
      title: 'Authorization Policy Controls (App Consent, App Registration, Guests)',
      category: 'Apps & Consent',
      severity: 'high',
      status: 'unavailable',
      currentValue: errText,
      expectedValue: 'Policy.Read.All + Policy.ReadWrite.Authorization granted',
      howToResolve: [
        'Grant Policy.Read.All (and Policy.ReadWrite.Authorization for 1-click fixes) to evaluate 7 tenant hardening controls.',
      ],
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.Authorization'],
    })
  }

  // 12. CIS 5.1.5.2 — Admin Consent Request Workflow
  if (snapshot.adminConsentPolicy) {
    const enabled = snapshot.adminConsentPolicy.isEnabled
    checks.push({
      id: 'admin_consent_workflow',
      cisRef: 'CIS 5.1.5.2',
      title: 'Enable Admin Consent Request Workflow for blocked apps',
      category: 'Apps & Consent',
      severity: 'medium',
      status: enabled ? 'pass' : 'fail',
      currentValue: enabled ? 'Enabled' : 'Disabled',
      expectedValue: 'Enabled (so users can request admin review when user consent is blocked)',
      howToResolve: [
        'Open Entra admin center → Identity → Applications → Enterprise applications → Consent and permissions → Admin consent settings.',
        'Set "Users can request admin consent to apps they are unable to consent to" to Yes and assign reviewers.',
      ],
      remediationId: !enabled ? 'enable_admin_consent_workflow' : undefined,
      remediationLabel: '1-Click: Enable Admin Consent Workflow',
      requiredPermissions: ['Policy.ReadWrite.ConsentRequest'],
    })
  } else if (snapshot.adminConsentPolicyError) {
    checks.push({
      id: 'admin_consent_workflow',
      cisRef: 'CIS 5.1.5.2',
      title: 'Enable Admin Consent Request Workflow for blocked apps',
      category: 'Apps & Consent',
      severity: 'medium',
      status: 'unavailable',
      currentValue: snapshot.adminConsentPolicyError,
      expectedValue: 'Enabled',
      howToResolve: [
        'Grant Policy.Read.All (and Policy.ReadWrite.ConsentRequest for 1-click enablement) in Entra ID.',
      ],
      requiredPermissions: ['Policy.Read.All', 'Policy.ReadWrite.ConsentRequest'],
    })
  }

  // 13. CIS 1.1.4 — Password Expiration Policy (NIST 800-63B / CIS modern guidance)
  if (snapshot.domains && snapshot.domains.length > 0) {
    const expiringDomains = snapshot.domains.filter(
      (d) =>
        d.isVerified &&
        d.passwordValidityPeriodInDays !== null &&
        d.passwordValidityPeriodInDays > 0 &&
        d.passwordValidityPeriodInDays < 2147483647,
    )
    checks.push({
      id: 'password_never_expires',
      cisRef: 'CIS 1.1.4',
      title: 'Ensure cloud user passwords are set to never expire (with MFA)',
      category: 'Identity & MFA',
      severity: 'medium',
      status: expiringDomains.length === 0 ? 'pass' : 'warn',
      currentValue:
        expiringDomains.length === 0
          ? 'No forced periodic password rotation on verified domains'
          : `Expiring passwords configured on: ${expiringDomains
              .map((d) => `${d.id} (${d.passwordValidityPeriodInDays}d)`)
              .join(', ')}`,
      expectedValue: 'Set passwords to never expire when MFA is enforced (NIST SP 800-63B & CIS)',
      howToResolve: [
        'Open Microsoft 365 admin center → Settings → Org settings → Security & privacy → Password expiration policy.',
        'Check "Set passwords to never expire (recommended)" and Save.',
      ],
      requiredPermissions: ['Organization.Read.All'],
    })
  }

  return checks
}

export function summarizeCisChecks(checks: CisCheckResult[]) {
  const passed = checks.filter((c) => c.status === 'pass').length
  const failed = checks.filter((c) => c.status === 'fail').length
  const warned = checks.filter((c) => c.status === 'warn').length
  const unavailable = checks.filter((c) => c.status === 'unavailable').length
  const evaluated = passed + failed + warned
  const scorePct = evaluated > 0 ? Math.round((passed / evaluated) * 100) : 0
  const oneClickFixable = checks.filter(
    (c) => (c.status === 'fail' || c.status === 'warn') && Boolean(c.remediationId),
  ).length

  return {
    total: checks.length,
    passed,
    failed,
    warned,
    unavailable,
    evaluated,
    scorePct,
    oneClickFixable,
  }
}
