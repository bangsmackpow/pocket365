import { describe, expect, it, vi } from 'vitest'
import {
  executeCisRemediation,
  REMEDIATION_TO_CHECK_ID,
} from './cis-remediation'
import type { MicrosoftGraphClient } from './client'

describe('CIS Remediation Engine', () => {
  it('maps all 17 remediation identifiers to known check targets', () => {
    expect(Object.keys(REMEDIATION_TO_CHECK_ID)).toHaveLength(17)
    expect(REMEDIATION_TO_CHECK_ID.enable_security_defaults).toBe('security_defaults')
    expect(REMEDIATION_TO_CHECK_ID.block_user_app_consent).toBe('user_app_consent')
    expect(REMEDIATION_TO_CHECK_ID.sp_disable_anonymous_links).toBe('sp_anonymous_links')
    expect(REMEDIATION_TO_CHECK_ID.enable_authenticator_context).toBe('auth_ms_authenticator_context')
  })

  it('executes security defaults remediation successfully', async () => {
    const mockGraph = {
      setSecurityDefaultsEnabled: vi.fn().mockResolvedValue(undefined),
    } as unknown as MicrosoftGraphClient

    const res = await executeCisRemediation(mockGraph, 'enable_security_defaults')
    expect(mockGraph.setSecurityDefaultsEnabled).toHaveBeenCalledWith(true)
    expect(res.targetCheckId).toBe('security_defaults')
    expect(res.summary).toContain('Enabled Microsoft Entra Security Defaults')
  })

  it('executes user app consent restriction successfully', async () => {
    const mockGraph = {
      getAuthorizationPolicy: vi.fn().mockResolvedValue({
        defaultUserRolePermissions: { allowedToCreateApps: true },
      }),
      updateAuthorizationPolicy: vi.fn().mockResolvedValue(undefined),
    } as unknown as MicrosoftGraphClient

    const res = await executeCisRemediation(mockGraph, 'block_user_app_consent')
    expect(mockGraph.updateAuthorizationPolicy).toHaveBeenCalledWith({
      defaultUserRolePermissions: {
        allowedToCreateApps: true,
        permissionGrantPoliciesAssigned: [],
      },
    })
    expect(res.targetCheckId).toBe('user_app_consent')
    expect(res.summary).toContain('Blocked unrestricted user app consent')
  })

  it('executes sharepoint anonymous link restriction successfully', async () => {
    const mockGraph = {
      updateSharePointSettings: vi.fn().mockResolvedValue(undefined),
    } as unknown as MicrosoftGraphClient

    const res = await executeCisRemediation(mockGraph, 'sp_disable_anonymous_links')
    expect(mockGraph.updateSharePointSettings).toHaveBeenCalledWith({
      sharingCapability: 'externalUserSharingOnly',
    })
    expect(res.targetCheckId).toBe('sp_anonymous_links')
    expect(res.summary).toContain('Disabled anonymous Anyone sharing links in SharePoint')
  })

  it('executes authenticator context enforcement successfully', async () => {
    const mockGraph = {
      setMicrosoftAuthenticatorContext: vi.fn().mockResolvedValue(undefined),
    } as unknown as MicrosoftGraphClient

    const res = await executeCisRemediation(mockGraph, 'enable_authenticator_context')
    expect(mockGraph.setMicrosoftAuthenticatorContext).toHaveBeenCalledWith(true)
    expect(res.targetCheckId).toBe('auth_ms_authenticator_context')
    expect(res.summary).toContain('Enabled application and location context')
  })
})
