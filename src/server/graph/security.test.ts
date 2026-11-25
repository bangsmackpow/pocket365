import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigCache } from '~/server/config'
import { closeDb, initDbForTesting } from '~/server/db'
import { listAuditLogs } from '~/server/db/audit'
import { isWeakMfaOnly, summarizeMfaCoverage } from './mfa-helpers'
import {
  resolveAuthMethodSegment,
  type GraphUserRegistrationDetail,
  type MicrosoftGraphClient,
} from './client'
import {
  enqueueJob,
  generateStrongPassword,
  processNextQueuedJob,
  stopJobWorker,
} from './jobs'

describe('User Security, MFA Coverage & Offboarding Wizard', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    resetConfigCache()
    initDbForTesting(':memory:')
  })

  afterEach(() => {
    stopJobWorker()
    closeDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('generates M365-compliant strong passwords', () => {
    const pw = generateStrongPassword(24)
    expect(pw.length).toBe(24)
    expect(/[A-Z]/.test(pw)).toBe(true)
    expect(/[a-z]/.test(pw)).toBe(true)
    expect(/[0-9]/.test(pw)).toBe(true)
    expect(/[^A-Za-z0-9]/.test(pw)).toBe(true)
  })

  it('resolves deletable Graph auth method segments and blocks password deletion', () => {
    expect(
      resolveAuthMethodSegment(
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
      ),
    ).toBe('microsoftAuthenticatorMethods')
    expect(
      resolveAuthMethodSegment('#microsoft.graph.phoneAuthenticationMethod'),
    ).toBe('phoneMethods')
    expect(
      resolveAuthMethodSegment('#microsoft.graph.fido2AuthenticationMethod'),
    ).toBe('fido2Methods')
    expect(
      resolveAuthMethodSegment('#microsoft.graph.passwordAuthenticationMethod'),
    ).toBeNull()
  })

  it('executes multi-step user.offboard job without leaking scrambled passwords', async () => {
    let capturedPassword = ''
    const fakeGraph = {
      setUserAccountEnabled: vi.fn().mockResolvedValue(undefined),
      revokeUserSignInSessions: vi.fn().mockResolvedValue(true),
      resetUserPassword: vi.fn().mockImplementation(async (_id, pw) => {
        capturedPassword = pw
      }),
      getUser: vi.fn().mockResolvedValue({
        id: 'u-100',
        assignedLicenses: [{ skuId: 'sku-1', disabledPlans: [] }],
      }),
      assignUserLicenses: vi.fn().mockResolvedValue({}),
      listUserDirectMemberships: vi.fn().mockResolvedValue([
        {
          id: 'grp-1',
          '@odata.type': '#microsoft.graph.group',
          displayName: 'All Staff',
          groupTypes: [],
        },
        {
          id: 'grp-dyn',
          '@odata.type': '#microsoft.graph.group',
          displayName: 'Dynamic Sales',
          groupTypes: ['DynamicMembership'],
        },
      ]),
      removeGroupMember: vi.fn().mockResolvedValue(undefined),
      clearUserManager: vi.fn().mockResolvedValue(undefined),
    } as unknown as MicrosoftGraphClient

    const actor = {
      oid: 'admin-1',
      upn: 'admin@contoso.com',
      role: 'admin' as const,
    }

    enqueueJob({
      type: 'user.offboard',
      payload: {
        userId: 'u-100',
        userPrincipalName: 'departing@contoso.com',
        mode: 'full_offboard',
        disableAccount: true,
        revokeSessions: true,
        scramblePassword: true,
        removeAllLicenses: true,
        removeFromGroups: true,
        clearManager: true,
      },
      actor,
      autoStartWorker: false,
    })

    const finished = await processNextQueuedJob(fakeGraph, 0)
    expect(finished?.status).toBe('completed')
    const result = JSON.parse(finished!.resultJson!)
    expect(result.failed).toBe(0)
    expect(result.succeeded).toBe(6) // disable, revoke, scramble, licenses, 1 non-dynamic group, clear manager

    // Dynamic group must NOT be removed
    expect(fakeGraph.removeGroupMember).toHaveBeenCalledTimes(1)
    expect(fakeGraph.removeGroupMember).toHaveBeenCalledWith('grp-1', 'u-100')

    // Generated password must NOT appear in job result or audit logs
    expect(capturedPassword.length).toBeGreaterThanOrEqual(20)
    expect(finished!.resultJson).not.toContain(capturedPassword)
    const audits = listAuditLogs({ limit: 10 })
    for (const a of audits) {
      expect(a.detailsJson).not.toContain(capturedPassword)
    }
  })

  it('summarizes MFA coverage, weak SMS-only accounts, and admins missing MFA', () => {
    const sample: GraphUserRegistrationDetail[] = [
      {
        id: '1',
        userPrincipalName: 'admin1@contoso.com',
        userDisplayName: 'Admin One',
        isAdmin: true,
        isSsprRegistered: false,
        isSsprEnabled: false,
        isSsprCapable: false,
        isMfaRegistered: false,
        isMfaCapable: false,
        isPasswordlessCapable: false,
        methodsRegistered: [],
      },
      {
        id: '2',
        userPrincipalName: 'sms@contoso.com',
        userDisplayName: 'SMS User',
        isAdmin: false,
        isSsprRegistered: true,
        isSsprEnabled: true,
        isSsprCapable: true,
        isMfaRegistered: true,
        isMfaCapable: true,
        isPasswordlessCapable: false,
        methodsRegistered: ['mobilePhone'],
      },
      {
        id: '3',
        userPrincipalName: 'fido@contoso.com',
        userDisplayName: 'FIDO User',
        isAdmin: true,
        isSsprRegistered: true,
        isSsprEnabled: true,
        isSsprCapable: true,
        isMfaRegistered: true,
        isMfaCapable: true,
        isPasswordlessCapable: true,
        methodsRegistered: ['fido2SecurityKey', 'microsoftAuthenticatorPush'],
      },
    ]

    expect(isWeakMfaOnly(sample[1]!)).toBe(true)
    expect(isWeakMfaOnly(sample[2]!)).toBe(false)

    const summary = summarizeMfaCoverage(sample)
    expect(summary.total).toBe(3)
    expect(summary.mfaRegistered).toBe(2)
    expect(summary.mfaMissing).toBe(1)
    expect(summary.adminsMissingMfa).toBe(1)
    expect(summary.weakMfaOnly).toBe(1)
    expect(summary.passwordlessCapable).toBe(1)
  })
})
