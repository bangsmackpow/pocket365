import { describe, expect, it } from 'vitest'
import {
  evaluateCisBenchmarks,
  GUEST_ROLE_IDS,
  summarizeCisChecks,
  type CisTenantSnapshot,
} from './cis-benchmarks'

describe('CIS Microsoft 365 Benchmarks Evaluator', () => {
  it('flags insecure defaults and offers 1-click remediations', () => {
    const insecure: CisTenantSnapshot = {
      securityDefaults: { id: 'sd', isEnabled: false },
      conditionalAccessEnabledCount: 0,
      adminConsentPolicy: { isEnabled: false },
      authorizationPolicy: {
        id: 'ap',
        allowInvitesFrom: 'everyone',
        guestUserRoleId: GUEST_ROLE_IDS.MEMBER_EQUIVALENT,
        blockMsolPowerShell: false,
        defaultUserRolePermissions: {
          allowedToCreateApps: true,
          allowedToCreateTenants: true,
          allowedToCreateSecurityGroups: true,
          permissionGrantPoliciesAssigned: [
            'ManagePermissionGrantsForSelf.microsoft-user-default-legacy',
          ],
        },
      },
      directoryRoles: [
        {
          id: 'r-ga',
          displayName: 'Global Administrator',
          description: null,
          roleTemplateId: '62e90394-69f5-4237-9190-012177145e10',
          members: [
            { id: '1' },
            { id: '2' },
            { id: '3' },
            { id: '4' },
            { id: '5' },
          ],
        },
      ],
      mfaRegistrations: [
        {
          id: '1',
          userPrincipalName: 'admin@contoso.com',
          userDisplayName: 'Admin',
          isAdmin: true,
          isSsprRegistered: false,
          isSsprEnabled: false,
          isSsprCapable: false,
          isMfaRegistered: false,
          isMfaCapable: false,
          isPasswordlessCapable: false,
          methodsRegistered: [],
        },
      ],
      domains: [
        {
          id: 'contoso.com',
          isDefault: true,
          isInitial: false,
          isVerified: true,
          passwordValidityPeriodInDays: 90,
          passwordNotificationWindowInDays: 14,
        },
      ],
    }

    const checks = evaluateCisBenchmarks(insecure)
    const summary = summarizeCisChecks(checks)

    expect(summary.failed).toBeGreaterThanOrEqual(10)
    expect(summary.oneClickFixable).toBe(10)
    expect(summary.scorePct).toBe(0)

    const byId = new Map(checks.map((c) => [c.id, c]))
    expect(byId.get('security_defaults')?.remediationId).toBe(
      'enable_security_defaults',
    )
    expect(byId.get('user_app_consent')?.remediationId).toBe(
      'block_user_app_consent',
    )
    expect(byId.get('guest_access_restriction')?.remediationId).toBe(
      'restrict_guest_access',
    )
    expect(byId.get('global_admin_count')?.status).toBe('fail')
    expect(byId.get('admin_mfa')?.status).toBe('fail')
    expect(byId.get('security_defaults')?.nistRef).toContain('NIST AC.L2-3.1.1')
    expect(byId.get('security_defaults')?.soc2Ref).toBe('SOC 2 CC6.1')
    expect(byId.get('security_defaults')?.isoRef).toContain('ISO 27001:2022 A.5.15')
    expect(byId.get('admin_mfa')?.nistRef).toContain('NIST IA.L2-3.5.3')
    expect(byId.get('admin_mfa')?.soc2Ref).toContain('SOC 2 CC6.1')
    expect(byId.get('admin_mfa')?.isoRef).toContain('ISO 27001:2022 A.8.2')
  })

  it('scores 100% pass for a hardened tenant configuration', () => {
    const hardened: CisTenantSnapshot = {
      securityDefaults: { id: 'sd', isEnabled: true },
      conditionalAccessEnabledCount: 0,
      adminConsentPolicy: { isEnabled: true },
      authorizationPolicy: {
        id: 'ap',
        allowInvitesFrom: 'adminsAndGuestInviters',
        guestUserRoleId: GUEST_ROLE_IDS.RESTRICTED,
        blockMsolPowerShell: true,
        allowEmailVerifiedUsersToJoinOrganization: false,
        defaultUserRolePermissions: {
          allowedToCreateApps: false,
          allowedToCreateTenants: false,
          allowedToCreateSecurityGroups: false,
          permissionGrantPoliciesAssigned: [],
        },
      },
      directoryRoles: [
        {
          id: 'r-ga',
          displayName: 'Global Administrator',
          description: null,
          roleTemplateId: '62e90394-69f5-4237-9190-012177145e10',
          members: [{ id: '1' }, { id: '2' }],
        },
      ],
      mfaRegistrations: [
        {
          id: '1',
          userPrincipalName: 'admin@contoso.com',
          userDisplayName: 'Admin',
          isAdmin: true,
          isSsprRegistered: true,
          isSsprEnabled: true,
          isSsprCapable: true,
          isMfaRegistered: true,
          isMfaCapable: true,
          isPasswordlessCapable: true,
          methodsRegistered: ['microsoftAuthenticatorPush'],
        },
      ],
      domains: [
        {
          id: 'contoso.com',
          isDefault: true,
          isInitial: false,
          isVerified: true,
          passwordValidityPeriodInDays: 2147483647,
          passwordNotificationWindowInDays: 14,
        },
      ],
    }

    const checks = evaluateCisBenchmarks(hardened)
    const summary = summarizeCisChecks(checks)

    expect(summary.failed).toBe(0)
    expect(summary.warned).toBe(0)
    expect(summary.scorePct).toBe(100)
    expect(summary.oneClickFixable).toBe(0)
  })

  it('evaluates Microsoft Authenticator context (CIS 5.2.3.1 / NIST IA.L2-3.5.3) and provides 1-click remediation', () => {
    const unhardenedAuth: CisTenantSnapshot = {
      securityDefaults: { id: 'sd', isEnabled: true },
      conditionalAccessEnabledCount: 1,
      adminConsentPolicy: { isEnabled: true },
      authorizationPolicy: {
        id: 'ap',
        allowInvitesFrom: 'adminsAndGuestInviters',
        guestUserRoleId: GUEST_ROLE_IDS.RESTRICTED,
        blockMsolPowerShell: true,
      },
      directoryRoles: [],
      mfaRegistrations: [],
      domains: [],
      authMethodsPolicy: {
        id: 'amp',
        authenticationMethodConfigurations: [
          {
            id: 'microsoftAuthenticator',
            state: 'enabled',
            featureSettings: {
              displayAppInformationRequiredState: { state: 'disabled' },
              displayLocationInformationRequiredState: { state: 'disabled' },
            },
          },
        ],
      },
    }

    const checks = evaluateCisBenchmarks(unhardenedAuth)
    const authCheck = checks.find((c) => c.id === 'auth_ms_authenticator_context')
    expect(authCheck).toBeDefined()
    expect(authCheck?.status).toBe('warn')
    expect(authCheck?.nistRef).toContain('NIST IA.L2-3.5.3')
    expect(authCheck?.soc2Ref).toBe('SOC 2 CC6.1')
    expect(authCheck?.isoRef).toContain('ISO 27001:2022 A.8.5')
    expect(authCheck?.remediationId).toBe('enable_authenticator_context')
    expect(authCheck?.remediationLabel).toBe(
      '1-Click: Enable Authenticator App & Location Context',
    )
    expect(authCheck?.howToResolve[0]).toContain('https://entra.microsoft.com')

    // Now test with context enabled
    const hardenedAuth: CisTenantSnapshot = {
      ...unhardenedAuth,
      authMethodsPolicy: {
        id: 'amp',
        authenticationMethodConfigurations: [
          {
            id: 'microsoftAuthenticator',
            state: 'enabled',
            featureSettings: {
              displayAppInformationRequiredState: { state: 'enabled' },
              displayLocationInformationRequiredState: { state: 'enabled' },
            },
          },
        ],
      },
    }

    const hardenedChecks = evaluateCisBenchmarks(hardenedAuth)
    const hardenedCheck = hardenedChecks.find(
      (c) => c.id === 'auth_ms_authenticator_context',
    )
    expect(hardenedCheck?.status).toBe('pass')
    expect(hardenedCheck?.remediationId).toBeUndefined()
  })
})
