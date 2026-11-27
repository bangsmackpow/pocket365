import type { MicrosoftGraphClient } from './client'
import {
  GUEST_ROLE_IDS,
  type CisRemediationId,
} from './cis-benchmarks'

export const REMEDIATION_TO_CHECK_ID: Record<CisRemediationId, string> = {
  enable_security_defaults: 'security_defaults',
  block_user_app_consent: 'user_app_consent',
  disable_user_app_registration: 'user_app_registration',
  disable_user_tenant_creation: 'user_tenant_creation',
  disable_user_security_group_creation: 'user_security_groups',
  restrict_guest_access: 'guest_access_restriction',
  restrict_guest_invites: 'guest_invite_restriction',
  block_msol_powershell: 'block_msol_powershell',
  enable_admin_consent_workflow: 'admin_consent_workflow',
  disable_email_verified_join: 'email_verified_join',
  enable_authenticator_context: 'auth_ms_authenticator_context',
  disable_sms_auth_method: 'auth_disable_sms',
  disable_voice_auth_method: 'auth_disable_voice',
  sp_disable_anonymous_links: 'sp_anonymous_links',
  sp_disable_external_resharing: 'sp_external_resharing',
  sp_block_legacy_auth: 'sp_legacy_auth',
  sp_enable_idle_signout: 'sp_idle_signout',
}

export async function executeCisRemediation(
  graph: MicrosoftGraphClient,
  id: CisRemediationId,
): Promise<{ summary: string; targetCheckId: string }> {
  const targetCheckId = REMEDIATION_TO_CHECK_ID[id]
  let summary = ''

  const patchDefaultRolePerms = async (
    updates: NonNullable<
      Awaited<ReturnType<typeof graph.getAuthorizationPolicy>>['defaultUserRolePermissions']
    >,
  ) => {
    const current = await graph.getAuthorizationPolicy()
    await graph.updateAuthorizationPolicy({
      defaultUserRolePermissions: {
        ...(current.defaultUserRolePermissions ?? {}),
        ...updates,
      },
    })
  }

  switch (id) {
    case 'enable_security_defaults':
      await graph.setSecurityDefaultsEnabled(true)
      summary = 'Enabled Microsoft Entra Security Defaults (CIS 5.2.2.1).'
      break
    case 'block_user_app_consent':
      await patchDefaultRolePerms({
        permissionGrantPoliciesAssigned: [],
      })
      summary = 'Blocked unrestricted user app consent (CIS 5.1.2.1).'
      break
    case 'disable_user_app_registration':
      await patchDefaultRolePerms({
        allowedToCreateApps: false,
      })
      summary = 'Disabled non-admin app registrations (CIS 5.1.2.2).'
      break
    case 'disable_user_tenant_creation':
      await patchDefaultRolePerms({
        allowedToCreateTenants: false,
      })
      summary = 'Blocked non-admin Entra tenant creation (CIS 5.1.2.3).'
      break
    case 'disable_user_security_group_creation':
      await patchDefaultRolePerms({
        allowedToCreateSecurityGroups: false,
      })
      summary = 'Restricted non-admin security group creation (CIS 5.1.2.4).'
      break
    case 'block_msol_powershell':
      await graph.updateAuthorizationPolicy({
        blockMsolPowerShell: true,
      })
      summary = 'Blocked legacy MSOL PowerShell for non-admins (CIS 5.1.2.5).'
      break
    case 'restrict_guest_access':
      await graph.updateAuthorizationPolicy({
        guestUserRoleId: GUEST_ROLE_IDS.RESTRICTED,
      })
      summary = 'Set guest directory access to most restrictive (CIS 5.1.2.6).'
      break
    case 'restrict_guest_invites':
      await graph.updateAuthorizationPolicy({
        allowInvitesFrom: 'adminsAndGuestInviters',
      })
      summary = 'Restricted external guest invitations to admins & Guest Inviters (CIS 5.1.6.2).'
      break
    case 'enable_admin_consent_workflow':
      await graph.setAdminConsentRequestEnabled(true)
      summary = 'Enabled Admin Consent Request Workflow (CIS 5.1.5.2).'
      break
    case 'disable_email_verified_join':
      await graph.updateAuthorizationPolicy({
        allowEmailVerifiedUsersToJoinOrganization: false,
      })
      summary = 'Blocked self-service email-verified tenant join (CIS 5.1.2.7).'
      break
    case 'enable_authenticator_context':
      await graph.setMicrosoftAuthenticatorContext(true)
      summary =
        'Enabled application and location context on Microsoft Authenticator push prompts (CIS 5.2.3.1 / NIST IA.L2-3.5.3).'
      break
    case 'disable_sms_auth_method':
      await graph.setAuthenticationMethodConfigState('Sms', 'disabled')
      summary = 'Disabled weak SMS authentication method (CIS 5.2.3.2).'
      break
    case 'disable_voice_auth_method':
      await graph.setAuthenticationMethodConfigState('Voice', 'disabled')
      summary = 'Disabled weak Voice authentication method (CIS 5.2.3.3).'
      break
    case 'sp_disable_anonymous_links':
      await graph.updateSharePointSettings({
        sharingCapability: 'externalUserSharingOnly',
      })
      summary = 'Disabled anonymous Anyone sharing links in SharePoint (CIS 7.2.1).'
      break
    case 'sp_disable_external_resharing':
      await graph.updateSharePointSettings({
        isResharingByExternalUsersEnabled: false,
      })
      summary = 'Blocked external guest resharing in SharePoint (CIS 7.2.2).'
      break
    case 'sp_block_legacy_auth':
      await graph.updateSharePointSettings({
        isLegacyAuthProtocolsEnabled: false,
      })
      summary = 'Blocked legacy authentication protocols in SharePoint (CIS 7.2.3).'
      break
    case 'sp_enable_idle_signout':
      await graph.updateSharePointSettings({
        idleSessionSignOut: {
          isEnabled: true,
          warnAfterInSeconds: 3300,
          signOutAfterInSeconds: 3600,
        },
      })
      summary = 'Enabled 60-minute SharePoint idle session sign-out (CIS 7.2.4).'
      break
  }

  return { summary, targetCheckId }
}
