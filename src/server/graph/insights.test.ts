import { describe, expect, it } from 'vitest'
import {
  analyzeAppCredentials,
  analyzeInboxRuleRisk,
  analyzeOAuthGrants,
  classifyStaleAccounts,
  diffConditionalAccessSnapshots,
} from './insights-helpers'

describe('Batch 4 Insights Helpers (Apps, Mailboxes, CA Drift, Stale Accounts)', () => {
  it('classifies expired, critical (<30d), warning (<60d), and healthy app secrets/certs', () => {
    const now = Date.parse('2026-11-25T00:00:00Z')
    const findings = analyzeAppCredentials(
      [
        {
          id: 'app-1',
          appId: 'client-1',
          displayName: 'Backup Sync',
          passwordCredentials: [
            {
              keyId: 'k-exp',
              displayName: 'Old Secret',
              endDateTime: '2026-11-01T00:00:00Z',
            },
            {
              keyId: 'k-crit',
              displayName: 'Soon Secret',
              endDateTime: '2026-12-10T00:00:00Z',
            },
          ],
          keyCredentials: [
            {
              keyId: 'k-warn',
              displayName: 'Cert',
              endDateTime: '2027-01-10T00:00:00Z',
            },
          ],
        },
      ],
      now,
    )

    expect(findings.map((f) => f.state)).toEqual([
      'expired',
      'critical',
      'warning',
    ])
  })

  it('flags high-risk delegated OAuth permission grants', () => {
    const spMap = new Map([
      ['sp-client', 'Suspicious Third-Party App'],
      ['sp-graph', 'Microsoft Graph'],
    ])
    const grants = analyzeOAuthGrants(
      [
        {
          id: 'g1',
          clientId: 'sp-client',
          consentType: 'AllPrincipals',
          principalId: null,
          resourceId: 'sp-graph',
          scope: 'User.Read Mail.ReadWrite offline_access',
        },
      ],
      spMap,
    )

    expect(grants[0]?.isHighRisk).toBe(true)
    expect(grants[0]?.riskyScopes).toEqual(['Mail.ReadWrite'])
    expect(grants[0]?.clientDisplayName).toBe('Suspicious Third-Party App')
  })

  it('detects BEC external forwarding and stealth deletion inbox rules', () => {
    const risky = analyzeInboxRuleRisk({
      id: 'r1',
      displayName: '...',
      isEnabled: true,
      actions: {
        forwardTo: [{ emailAddress: { address: 'attacker@evil.example' } }],
        markAsRead: true,
        delete: true,
      },
    })
    expect(risky.riskLevel).toBe('high')
    expect(risky.forwardTargets).toEqual(['attacker@evil.example'])

    const benign = analyzeInboxRuleRisk({
      id: 'r2',
      displayName: 'Newsletter Folder',
      isEnabled: true,
      actions: { moveToFolder: 'Newsletters' },
    })
    expect(benign.riskLevel).toBe('low')
  })

  it('computes Netwrix-style Conditional Access policy drift between snapshots', () => {
    const baseline = [
      { id: 'p1', displayName: 'Require MFA', state: 'enabled' as const },
      { id: 'p2', displayName: 'Block Legacy Auth', state: 'enabled' as const },
    ]
    const current = [
      { id: 'p1', displayName: 'Require MFA', state: 'disabled' as const },
      {
        id: 'p3',
        displayName: 'Geo Block',
        state: 'enabledForReportingButNotEnforced' as const,
      },
    ]

    const diff = diffConditionalAccessSnapshots(baseline, current)
    expect(diff.hasDrift).toBe(true)
    expect(diff.added).toBe(1)
    expect(diff.removed).toBe(1)
    expect(diff.modified).toBe(1)
  })

  it('identifies disabled users holding paid licenses and stale guests', () => {
    const now = Date.parse('2026-11-25T00:00:00Z')
    const rows = classifyStaleAccounts(
      [
        {
          id: 'u1',
          displayName: 'Former Employee',
          userPrincipalName: 'former@contoso.com',
          mail: 'former@contoso.com',
          accountEnabled: false,
          jobTitle: null,
          department: null,
          officeLocation: null,
          userType: 'Member',
          assignedLicenses: [{ skuId: 'sku-1', disabledPlans: [] }],
          signInActivity: { lastSignInDateTime: '2026-08-01T00:00:00Z' },
        },
        {
          id: 'u2',
          displayName: 'Old Guest',
          userPrincipalName: 'vendor_gmail.com#EXT#@contoso.onmicrosoft.com',
          mail: 'vendor@gmail.com',
          accountEnabled: true,
          jobTitle: null,
          department: null,
          officeLocation: null,
          userType: 'Guest',
          assignedLicenses: [],
        },
      ],
      30,
      new Map(),
      now,
    )

    expect(rows[0]?.flags).toContain('disabled_with_license')
    expect(rows[1]?.userType).toBe('Guest')
    expect(rows[1]?.flags).toContain('stale_guest')
  })
})
