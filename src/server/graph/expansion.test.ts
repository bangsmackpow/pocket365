import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  formatWebhookPayload,
  recordAndDispatchAlert,
} from '~/server/alerts/engine'
import { resetConfigCache } from '~/server/config'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import { evaluateCisBenchmarks } from './cis-benchmarks'
import type { MicrosoftGraphClient } from './client'
import {
  auditDomainEmailAuth,
  evaluateDmarcRecord,
  evaluateSpfRecord,
} from './dns-email-auth'
import { enqueueJob, processNextQueuedJob } from './jobs'

describe('Deep CIS Expansion, DNS Email Auth, BEC Sweep & Alerting', () => {
  beforeEach(() => {
    resetConfigCache()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    resetConfigCache()
  })

  it('audits SPF, DKIM, and DMARC DNS records accurately', async () => {
    expect(
      evaluateSpfRecord(['v=spf1 include:spf.protection.outlook.com -all'])
        .status,
    ).toBe('pass')
    expect(evaluateSpfRecord(['v=spf1 +all']).status).toBe('fail')
    expect(
      evaluateDmarcRecord(['v=DMARC1; p=reject; rua=mailto:d@ex.com']).status,
    ).toBe('pass')
    expect(evaluateDmarcRecord(['v=DMARC1; p=none']).status).toBe('warn')

    const audit = await auditDomainEmailAuth('contoso.com', {
      resolveTxt: async (host) => {
        if (host === 'contoso.com') {
          return [['v=spf1 include:spf.protection.outlook.com -all']]
        }
        if (host === '_dmarc.contoso.com') {
          return [['v=DMARC1; p=quarantine']]
        }
        return []
      },
      resolveCname: async (host) => {
        if (host.startsWith('selector1.')) {
          return ['selector1-contoso._domainkey.contoso.onmicrosoft.com']
        }
        return []
      },
    })

    expect(audit.spfStatus).toBe('pass')
    expect(audit.dmarcStatus).toBe('pass')
    expect(audit.dkimStatus).toBe('warn')
  })

  it('evaluates expanded CIS controls for DNS, Auth Methods, and SharePoint', () => {
    const checks = evaluateCisBenchmarks({
      authorizationPolicy: null,
      securityDefaults: null,
      adminConsentPolicy: null,
      conditionalAccessEnabledCount: 0,
      directoryRoles: null,
      mfaRegistrations: null,
      domains: null,
      emailAuthAudits: [
        {
          domain: 'contoso.com',
          spfRecord: null,
          spfStatus: 'fail',
          spfDetail: 'Missing',
          dmarcRecord: null,
          dmarcPolicy: 'missing',
          dmarcStatus: 'fail',
          dmarcDetail: 'Missing',
          dkimSelector1: null,
          dkimSelector2: null,
          dkimStatus: 'fail',
          dkimDetail: 'Missing',
        },
      ],
      authMethodsPolicy: {
        id: 'authenticationMethodsPolicy',
        authenticationMethodConfigurations: [
          { id: 'Sms', state: 'enabled' },
          { id: 'Voice', state: 'enabled' },
          {
            id: 'MicrosoftAuthenticator',
            state: 'enabled',
            featureSettings: {
              displayAppInformationRequiredState: { state: 'enabled' },
              displayLocationInformationRequiredState: { state: 'enabled' },
            },
          },
        ],
      },
      sharePointSettings: {
        sharingCapability: 'externalUserAndGuestSharing',
        isLegacyAuthProtocolsEnabled: true,
        isResharingByExternalUsersEnabled: true,
        idleSessionSignOut: { isEnabled: false },
      },
    })

    const byId = new Map(checks.map((c) => [c.id, c]))
    expect(byId.get('dns_spf')?.status).toBe('fail')
    expect(byId.get('dns_dmarc')?.status).toBe('fail')
    expect(byId.get('auth_ms_authenticator_context')?.status).toBe('pass')
    expect(byId.get('auth_disable_sms')?.remediationId).toBe(
      'disable_sms_auth_method',
    )
    expect(byId.get('sp_anonymous_links')?.remediationId).toBe(
      'sp_disable_anonymous_links',
    )
    expect(byId.get('sp_legacy_auth')?.remediationId).toBe('sp_block_legacy_auth')
  })

  it('runs tenant-wide mailbox BEC sweep async job and flags forwarding rules', async () => {
    const fakeGraph = {
      listUsers: vi.fn().mockResolvedValue({
        items: [
          {
            id: 'u1',
            displayName: 'CFO',
            userPrincipalName: 'cfo@contoso.com',
            accountEnabled: true,
            assignedLicenses: [{ skuId: 'sku1', disabledPlans: [] }],
          },
          {
            id: 'u2',
            displayName: 'Shared NoLic',
            userPrincipalName: 'shared@contoso.com',
            accountEnabled: true,
            assignedLicenses: [],
          },
        ],
        nextLink: null,
      }),
      listUserInboxRules: vi.fn().mockResolvedValue([
        {
          id: 'rule-evil',
          displayName: '...',
          isEnabled: true,
          actions: {
            forwardTo: [{ emailAddress: { address: 'drop@attacker.example' } }],
            markAsRead: true,
          },
        },
      ]),
    } as unknown as MicrosoftGraphClient

    await enqueueJob({
      type: 'mailbox.bec_sweep',
      payload: { onlyLicensed: true, maxUsers: 50 },
      actor: { oid: 'admin-1', upn: 'admin@contoso.com', role: 'admin' },
      autoStartWorker: false,
    })

    const finished = await processNextQueuedJob(fakeGraph, 0)
    expect(finished?.status).toBe('completed')
    const parsed = JSON.parse(finished!.resultJson!)
    expect(parsed.scannedUsers).toBe(1)
    expect(parsed.highRiskCount).toBe(1)
    expect(parsed.findings[0].rule.forwardTargets).toEqual([
      'drop@attacker.example',
    ])
  })

  it('formats webhook payloads and deduplicates repeated alerts within 24h', async () => {
    const teamsPayload = formatWebhookPayload('teams', {
      ruleKey: 'privileged_role_change',
      dedupeKey: 'k1',
      severity: 'critical',
      title: 'New Global Admin',
      message: 'User added',
    })
    expect(teamsPayload['@type']).toBe('MessageCard')

    const first = await recordAndDispatchAlert({
      ruleKey: 'cis_regression',
      dedupeKey: 'cis_regress:security_defaults',
      severity: 'critical',
      title: 'CIS Regression',
      message: 'Security Defaults disabled',
    })
    expect(first.skipped).toBe(false)

    const duplicate = await recordAndDispatchAlert({
      ruleKey: 'cis_regression',
      dedupeKey: 'cis_regress:security_defaults',
      severity: 'critical',
      title: 'CIS Regression',
      message: 'Security Defaults disabled',
    })
    expect(duplicate.skipped).toBe(true)
  })
})
