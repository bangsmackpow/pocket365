import type {
  GraphAdminConsentRequestPolicy,
  GraphAuthMethodsPolicy,
  GraphAuthorizationPolicy,
  GraphDirectoryRole,
  GraphDomain,
  GraphSecurityDefaultsPolicy,
  GraphSharePointSettings,
  GraphUserRegistrationDetail,
} from './client'
import type { DomainEmailAuthAudit } from './dns-email-auth'
import { isWeakMfaOnly } from './mfa-helpers'

export type CisStatus = 'pass' | 'fail' | 'warn' | 'unavailable'
export type CisSeverity = 'critical' | 'high' | 'medium'
export type CisCategory =
  | 'Identity & MFA'
  | 'Privileged Access'
  | 'Apps & Consent'
  | 'Guests & Collaboration'
  | 'Email & DNS Security'
  | 'SharePoint & OneDrive'

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
  | 'disable_email_verified_join'
  | 'enable_authenticator_context'
  | 'disable_sms_auth_method'
  | 'disable_voice_auth_method'
  | 'sp_disable_anonymous_links'
  | 'sp_disable_external_resharing'
  | 'sp_block_legacy_auth'
  | 'sp_enable_idle_signout'

export interface CisCheckResult {
  id: string
  cisRef: string
  nistRef?: string
  nistTitle?: string
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
  emailAuthAudits?: DomainEmailAuthAudit[] | null
  sharePointSettings?: GraphSharePointSettings | null
  sharePointSettingsError?: string | null
  authMethodsPolicy?: GraphAuthMethodsPolicy | null
  authMethodsPolicyError?: string | null
}

export const NIST_MAPPING_BY_ID: Record<
  string,
  { nistRef: string; nistTitle: string }
> = {
  security_defaults: {
    nistRef: 'NIST AC.L2-3.1.1 / CSF PR.AA-01',
    nistTitle: 'Enforce Multi-Factor Authentication for System Access',
  },
  admin_mfa: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-03',
    nistTitle: 'Multifactor Authentication for Privileged Access',
  },
  all_users_mfa: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-01',
    nistTitle: 'Multifactor Authentication for All Organizational Users',
  },
  global_admin_count: {
    nistRef: 'NIST AC.L2-3.1.5 / CSF PR.AA-05',
    nistTitle: 'Principle of Least Privilege for Administrative Accounts',
  },
  user_app_consent: {
    nistRef: 'NIST AC.L2-3.1.2 / CSF PR.AC-04',
    nistTitle: 'Limit Access by External Applications to Organizational Data',
  },
  user_app_registration: {
    nistRef: 'NIST CM.L2-3.4.5 / CSF PR.PS-02',
    nistTitle: 'Access Restrictions for Software and Application Registration',
  },
  user_tenant_creation: {
    nistRef: 'NIST AC.L2-3.1.1 / CSF PR.AC-01',
    nistTitle: 'Limit Organizational Boundary Crossing & Tenant Sprawl',
  },
  user_security_groups: {
    nistRef: 'NIST AC.L2-3.1.2 / CSF PR.AA-05',
    nistTitle: 'Authorized Group Creation and Membership Management',
  },
  block_msol_powershell: {
    nistRef: 'NIST AC.L2-3.1.12 / CSF PR.AC-03',
    nistTitle: 'Control and Restrict Legacy Remote Management Protocols',
  },
  guest_access_restriction: {
    nistRef: 'NIST AC.L2-3.1.20 / CSF PR.AA-06',
    nistTitle: 'Limit External and Guest Access to Least Privilege',
  },
  guest_invite_restriction: {
    nistRef: 'NIST AC.L2-3.1.20 / CSF PR.AA-06',
    nistTitle: 'Authorize External Sharing and Guest Collaborators',
  },
  email_verified_join: {
    nistRef: 'NIST IA.L2-3.5.1 / CSF PR.AC-01',
    nistTitle: 'Authenticate and Control Directory Account Provisioning',
  },
  authorization_policy_unavailable: {
    nistRef: 'NIST AC.L2-3.1.1 / CSF PR.AC-01',
    nistTitle: 'Authorization Policy Inspection',
  },
  admin_consent_workflow: {
    nistRef: 'NIST AC.L2-3.1.2 / CSF PR.AC-04',
    nistTitle: 'Formal Access Approval Workflow for Third-Party Applications',
  },
  password_never_expires: {
    nistRef: 'NIST IA.L2-3.5.7 / CSF PR.AC-01',
    nistTitle: 'Password Complexity and Lifecycle Aligned with MFA (SP 800-63B)',
  },
  dns_spf: {
    nistRef: 'NIST SC.L2-3.13.1 / CSF PR.DS-02',
    nistTitle: 'Domain Sender Policy Framework (SPF) Verification',
  },
  dns_dkim: {
    nistRef: 'NIST SC.L2-3.13.1 / CSF PR.DS-02',
    nistTitle: 'Cryptographic Message Integrity via DKIM Signatures',
  },
  dns_dmarc: {
    nistRef: 'NIST SC.L2-3.13.1 / CSF PR.DS-02',
    nistTitle: 'Domain Message Authentication, Reporting & Conformance (DMARC)',
  },
  auth_ms_authenticator_context: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-03',
    nistTitle: 'Context-Rich & Number-Matching MFA Prompt Hardening',
  },
  auth_disable_sms: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-01',
    nistTitle: 'Deprecate Weak Out-of-Band SMS Authentication (SP 800-63B)',
  },
  auth_disable_voice: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-01',
    nistTitle: 'Deprecate Weak PSTN Voice Authentication (SP 800-63B)',
  },
  auth_methods_unavailable: {
    nistRef: 'NIST IA.L2-3.5.3 / CSF PR.AA-01',
    nistTitle: 'Authentication Methods Policy Inspection',
  },
  sp_external_resharing: {
    nistRef: 'NIST AC.L2-3.1.20 / CSF PR.DS-05',
    nistTitle: 'Prevent Unauthorized Data Resharing by External Parties',
  },
  sp_legacy_auth: {
    nistRef: 'NIST AC.L2-3.1.12 / CSF PR.AC-03',
    nistTitle: 'Prohibit Unencrypted / Legacy Authentication in Portals',
  },
  sp_idle_signout: {
    nistRef: 'NIST AC.L2-3.1.10 / CSF PR.AC-05',
    nistTitle: 'Enforce Automatic Session Termination & Inactivity Timeouts',
  },
  sp_settings_unavailable: {
    nistRef: 'NIST AC.L2-3.1.20 / CSF PR.DS-05',
    nistTitle: 'SharePoint & OneDrive Security Inspection',
  },
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

    // 11b. CIS 5.1.2.7 — Block self-service email-verified tenant join
    const allowSelfJoin =
      authPol.allowEmailVerifiedUsersToJoinOrganization !== false
    checks.push({
      id: 'email_verified_join',
      cisRef: 'CIS 5.1.2.7',
      title: 'Block self-service email-verified sign-up to join tenant',
      category: 'Guests & Collaboration',
      severity: 'medium',
      status: !allowSelfJoin ? 'pass' : 'fail',
      currentValue: allowSelfJoin
        ? 'Allowed (allowEmailVerifiedUsersToJoinOrganization = true)'
        : 'Blocked (allowEmailVerifiedUsersToJoinOrganization = false)',
      expectedValue: 'allowEmailVerifiedUsersToJoinOrganization = false',
      howToResolve: [
        'Disable viral/self-service sign-ups so unapproved users cannot create ad-hoc accounts in your tenant using a verified domain email.',
      ],
      remediationId: allowSelfJoin ? 'disable_email_verified_join' : undefined,
      remediationLabel: '1-Click: Block Self-Service Join',
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

  // 14-16. CIS Section 2 — Email Authentication & Anti-Spoofing (SPF / DKIM / DMARC via Live DNS)
  const emailAudits = snapshot.emailAuthAudits ?? []
  if (emailAudits.length > 0) {
    const spfFailed = emailAudits.filter((a) => a.spfStatus === 'fail')
    const spfWarned = emailAudits.filter((a) => a.spfStatus === 'warn')
    checks.push({
      id: 'dns_spf',
      cisRef: 'CIS 2.1.6',
      title: 'Publish strict SPF DNS records for all verified custom domains',
      category: 'Email & DNS Security',
      severity: 'high',
      status:
        spfFailed.length > 0 ? 'fail' : spfWarned.length > 0 ? 'warn' : 'pass',
      currentValue: emailAudits
        .map((a) => `${a.domain}: ${a.spfRecord ? a.spfRecord : 'MISSING'}`)
        .join(' | '),
      expectedValue:
        'TXT v=spf1 include:spf.protection.outlook.com -all (or ~all) on every verified domain',
      howToResolve: [
        'In your DNS provider, publish a TXT record on the root (@) of each custom domain:',
        'v=spf1 include:spf.protection.outlook.com -all',
        'Include any authorized third-party senders (e.g., CRM/transactional mailers) before -all and stay under 10 DNS lookups.',
      ],
      requiredPermissions: ['Organization.Read.All'],
    })

    const dkimFailed = emailAudits.filter((a) => a.dkimStatus === 'fail')
    const dkimWarned = emailAudits.filter((a) => a.dkimStatus === 'warn')
    checks.push({
      id: 'dns_dkim',
      cisRef: 'CIS 2.1.7',
      title: 'Enable DKIM signing (selector1 & selector2 CNAMEs) for custom domains',
      category: 'Email & DNS Security',
      severity: 'high',
      status:
        dkimFailed.length > 0 ? 'fail' : dkimWarned.length > 0 ? 'warn' : 'pass',
      currentValue: emailAudits
        .map(
          (a) =>
            `${a.domain}: sel1=${a.dkimSelector1 ? 'OK' : 'MISSING'}, sel2=${a.dkimSelector2 ? 'OK' : 'MISSING'}`,
        )
        .join(' | '),
      expectedValue:
        'Both selector1._domainkey and selector2._domainkey CNAME records published and DKIM enabled in Defender portal',
      howToResolve: [
        'Open Microsoft 365 Defender portal → Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM.',
        'Select each custom domain → click "Create DKIM keys" → publish the two CNAME records (selector1._domainkey & selector2._domainkey) in DNS → toggle Enable.',
      ],
      requiredPermissions: ['Organization.Read.All'],
    })

    const dmarcFailed = emailAudits.filter((a) => a.dmarcStatus === 'fail')
    const dmarcWarned = emailAudits.filter((a) => a.dmarcStatus === 'warn')
    checks.push({
      id: 'dns_dmarc',
      cisRef: 'CIS 2.1.8',
      title: 'Enforce DMARC (p=quarantine or p=reject) for all custom domains',
      category: 'Email & DNS Security',
      severity: 'critical',
      status:
        dmarcFailed.length > 0
          ? 'fail'
          : dmarcWarned.length > 0
            ? 'warn'
            : 'pass',
      currentValue: emailAudits
        .map((a) => `${a.domain}: ${a.dmarcRecord ? `p=${a.dmarcPolicy}` : 'MISSING'}`)
        .join(' | '),
      expectedValue:
        '_dmarc.<domain> TXT record with p=quarantine or p=reject (not p=none)',
      howToResolve: [
        'Publish a TXT record at _dmarc.<your-domain> after SPF & DKIM pass:',
        'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@<your-domain>',
        'Monitor aggregate reports, then tighten to p=reject.',
      ],
      requiredPermissions: ['Organization.Read.All'],
    })
  }

  // 17-19. CIS Section 5.2.3 — Authentication Methods Policy
  if (snapshot.authMethodsPolicy?.authenticationMethodConfigurations) {
    const configs =
      snapshot.authMethodsPolicy.authenticationMethodConfigurations
    const findConfig = (id: string) =>
      configs.find((c) => c.id.toLowerCase() === id.toLowerCase())

    const msAuth = findConfig('MicrosoftAuthenticator')
    const sms = findConfig('Sms')
    const voice = findConfig('Voice')

    if (msAuth) {
      const appCtx =
        msAuth.featureSettings?.displayAppInformationRequiredState?.state ===
        'enabled'
      const locCtx =
        msAuth.featureSettings?.displayLocationInformationRequiredState?.state ===
        'enabled'
      const authReady = msAuth.state === 'enabled' && appCtx && locCtx
      checks.push({
        id: 'auth_ms_authenticator_context',
        cisRef: 'CIS 5.2.3.1',
        title: 'Show application & location context in Microsoft Authenticator prompts',
        category: 'Identity & MFA',
        severity: 'high',
        status: authReady ? 'pass' : msAuth.state === 'enabled' ? 'warn' : 'fail',
        currentValue: `state=${msAuth.state}, appContext=${appCtx ? 'enabled' : 'off'}, locationContext=${locCtx ? 'enabled' : 'off'}`,
        expectedValue:
          'Microsoft Authenticator enabled with application name and geographic location shown on MFA prompts',
        howToResolve: [
          'Direct link: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods',
          'Open Microsoft Entra admin center (entra.microsoft.com) → Protection → Authentication methods → Policies.',
          'Select Microsoft Authenticator → Click Configure tab at the top.',
          'Set "Show application name in push and passwordless notifications" and "Show geographic location in push and passwordless notifications" to Enabled for All users.',
        ],
        remediationId: !authReady ? 'enable_authenticator_context' : undefined,
        remediationLabel: '1-Click: Enable Authenticator App & Location Context',
        requiredPermissions: [
          'Policy.Read.All',
          'Policy.ReadWrite.AuthenticationMethod',
        ],
      })
    }

    if (sms) {
      const smsDisabled = sms.state === 'disabled'
      checks.push({
        id: 'auth_disable_sms',
        cisRef: 'CIS 5.2.3.2',
        title: 'Disable weak SMS authentication method (phishing / SIM-swap risk)',
        category: 'Identity & MFA',
        severity: 'medium',
        status: smsDisabled ? 'pass' : 'warn',
        currentValue: `SMS authentication method state = ${sms.state}`,
        expectedValue: 'SMS state = disabled (use Microsoft Authenticator or FIDO2 instead)',
        howToResolve: [
          'Verify users have migrated off SMS using Pocket365 → MFA Coverage → Weak MFA (SMS/Voice).',
          'Open Entra admin center → Protection → Authentication methods → SMS → set Enable to Off.',
        ],
        remediationId: !smsDisabled ? 'disable_sms_auth_method' : undefined,
        remediationLabel: '1-Click: Disable SMS Auth Method',
        requiredPermissions: ['Policy.ReadWrite.AuthenticationMethod'],
      })
    }

    if (voice) {
      const voiceDisabled = voice.state === 'disabled'
      checks.push({
        id: 'auth_disable_voice',
        cisRef: 'CIS 5.2.3.3',
        title: 'Disable weak Voice Call authentication method',
        category: 'Identity & MFA',
        severity: 'medium',
        status: voiceDisabled ? 'pass' : 'warn',
        currentValue: `Voice authentication method state = ${voice.state}`,
        expectedValue: 'Voice state = disabled',
        howToResolve: [
          'Ensure users have strong MFA registered, then open Entra admin center → Protection → Authentication methods → Voice call → disable.',
        ],
        remediationId: !voiceDisabled ? 'disable_voice_auth_method' : undefined,
        remediationLabel: '1-Click: Disable Voice Auth Method',
        requiredPermissions: ['Policy.ReadWrite.AuthenticationMethod'],
      })
    }
  } else if (snapshot.authMethodsPolicyError) {
    checks.push({
      id: 'auth_methods_unavailable',
      cisRef: 'CIS 5.2.3.x',
      title: 'Authentication Methods Policy (Authenticator Context, SMS/Voice Hardening)',
      category: 'Identity & MFA',
      severity: 'medium',
      status: 'unavailable',
      currentValue: snapshot.authMethodsPolicyError,
      expectedValue: 'Policy.Read.All + Policy.ReadWrite.AuthenticationMethod',
      howToResolve: [
        'Grant Policy.Read.All and Policy.ReadWrite.AuthenticationMethod in Entra ID.',
      ],
      requiredPermissions: [
        'Policy.Read.All',
        'Policy.ReadWrite.AuthenticationMethod',
      ],
    })
  }

  // 20-23. CIS Section 7 — SharePoint & OneDrive Hardening
  const sp = snapshot.sharePointSettings
  if (sp) {
    const anonAllowed =
      sp.sharingCapability === 'externalUserAndGuestSharing'
    checks.push({
      id: 'sp_anonymous_links',
      cisRef: 'CIS 7.2.1',
      title: 'Disable anonymous "Anyone" sharing links in SharePoint & OneDrive',
      category: 'SharePoint & OneDrive',
      severity: 'high',
      status: !anonAllowed ? 'pass' : 'fail',
      currentValue: `sharingCapability = ${sp.sharingCapability || 'unknown'}`,
      expectedValue:
        'externalUserSharingOnly, existingExternalUserSharingOnly, or disabled (no unauthenticated Anyone links)',
      howToResolve: [
        'Open SharePoint admin center → Policies → Sharing.',
        'Drag the SharePoint & OneDrive sliders down from "Anyone" to "New and existing guests" (or stricter) and Save.',
      ],
      remediationId: anonAllowed ? 'sp_disable_anonymous_links' : undefined,
      remediationLabel: '1-Click: Disable Anonymous Sharing Links',
      requiredPermissions: ['SharePointTenantSettings.ReadWrite.All'],
    })

    const externalReshare = sp.isResharingByExternalUsersEnabled !== false
    checks.push({
      id: 'sp_external_resharing',
      cisRef: 'CIS 7.2.2',
      title: 'Prevent external guests from resharing SharePoint items they do not own',
      category: 'SharePoint & OneDrive',
      severity: 'medium',
      status: !externalReshare ? 'pass' : 'fail',
      currentValue: externalReshare
        ? 'Allowed (isResharingByExternalUsersEnabled = true)'
        : 'Blocked (isResharingByExternalUsersEnabled = false)',
      expectedValue: 'isResharingByExternalUsersEnabled = false',
      howToResolve: [
        'Open SharePoint admin center → Policies → Sharing → More external sharing settings.',
        'Uncheck "Allow guests to share items they don\'t own" and Save.',
      ],
      remediationId: externalReshare ? 'sp_disable_external_resharing' : undefined,
      remediationLabel: '1-Click: Block Guest Resharing',
      requiredPermissions: ['SharePointTenantSettings.ReadWrite.All'],
    })

    const spLegacy = sp.isLegacyAuthProtocolsEnabled !== false
    checks.push({
      id: 'sp_legacy_auth',
      cisRef: 'CIS 7.2.3',
      title: 'Block legacy authentication protocols in SharePoint Online',
      category: 'SharePoint & OneDrive',
      severity: 'high',
      status: !spLegacy ? 'pass' : 'fail',
      currentValue: spLegacy
        ? 'Legacy auth enabled (isLegacyAuthProtocolsEnabled = true)'
        : 'Blocked (isLegacyAuthProtocolsEnabled = false)',
      expectedValue: 'isLegacyAuthProtocolsEnabled = false',
      howToResolve: [
        'Open SharePoint admin center → Policies → Access control → Apps that don\'t use modern authentication.',
        'Select "Block access" and Save.',
      ],
      remediationId: spLegacy ? 'sp_block_legacy_auth' : undefined,
      remediationLabel: '1-Click: Block SharePoint Legacy Auth',
      requiredPermissions: ['SharePointTenantSettings.ReadWrite.All'],
    })

    const idleOn = sp.idleSessionSignOut?.isEnabled === true
    checks.push({
      id: 'sp_idle_signout',
      cisRef: 'CIS 7.2.4',
      title: 'Enable idle session sign-out for SharePoint & OneDrive web sessions',
      category: 'SharePoint & OneDrive',
      severity: 'medium',
      status: idleOn ? 'pass' : 'warn',
      currentValue: idleOn
        ? `Enabled (sign out after ${Math.round((sp.idleSessionSignOut?.signOutAfterInSeconds ?? 0) / 60)} min)`
        : 'Disabled',
      expectedValue: 'Idle session sign-out enabled (e.g., 60 min sign-out / 55 min warning)',
      howToResolve: [
        'Open SharePoint admin center → Policies → Access control → Idle session sign-out.',
        'Enable "Sign out inactive users automatically" and set timeout (e.g., 1 hour).',
      ],
      remediationId: !idleOn ? 'sp_enable_idle_signout' : undefined,
      remediationLabel: '1-Click: Enable Idle Sign-out (60m)',
      requiredPermissions: ['SharePointTenantSettings.ReadWrite.All'],
    })
  } else if (snapshot.sharePointSettingsError) {
    checks.push({
      id: 'sp_settings_unavailable',
      cisRef: 'CIS 7.2.x',
      title: 'SharePoint & OneDrive External Sharing and Legacy Auth Controls',
      category: 'SharePoint & OneDrive',
      severity: 'high',
      status: 'unavailable',
      currentValue: snapshot.sharePointSettingsError,
      expectedValue: 'SharePointTenantSettings.ReadWrite.All granted',
      howToResolve: [
        'Grant SharePointTenantSettings.ReadWrite.All (Application permission + Admin Consent) in Entra ID to audit and 1-click harden SharePoint & OneDrive.',
      ],
      requiredPermissions: ['SharePointTenantSettings.ReadWrite.All'],
    })
  }

  return checks.map((c) => {
    const nist = NIST_MAPPING_BY_ID[c.id]
    return {
      ...c,
      nistRef: nist?.nistRef ?? 'NIST SP 800-171',
      nistTitle: nist?.nistTitle ?? c.title,
    }
  })
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
