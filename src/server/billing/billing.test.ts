import crypto from 'node:crypto'
import { exportPKCS8, exportSPKI, generateKeyPair } from 'jose'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetConfigCache } from '~/server/config'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import {
  EntitlementHttpError,
  getActivePlan,
  issueSignedLicenseKey,
  persistLicenseState,
  requireEntitlement,
  verifySignedLicenseKey,
} from './entitlements'
import {
  resolveTierFromStripePriceId,
  verifyStripeWebhookSignature,
} from './stripe-webhook'

describe('Phase 3 Tier Entitlements, Ed25519 Licensing & Stripe Webhooks', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      SESSION_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
      LICENSE_ENFORCEMENT: 'strict',
      POCKET365_TIER: 'community',
    }
    resetConfigCache()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('enforces tier entitlements strictly when LICENSE_ENFORCEMENT=strict and allows all when off', async () => {
    await expect(requireEntitlement('core.signins')).resolves.toBeTruthy()
    await expect(requireEntitlement('cis.autofix')).rejects.toThrowError(
      EntitlementHttpError,
    )
    await expect(requireEntitlement('tenants.multi_tenant')).rejects.toThrowError(
      EntitlementHttpError,
    )

    // Upgrade stored plan to pro
    await persistLicenseState({
      source: 'license_key',
      tier: 'pro',
      licensee: 'Contoso IT',
      updatedBy: 'admin@contoso.com',
    })
    await expect(requireEntitlement('cis.autofix')).resolves.toBeTruthy()
    await expect(requireEntitlement('tenants.multi_tenant')).rejects.toThrowError(
      EntitlementHttpError,
    )

    // Open self-hosted mode unlocks all single-tenant Pro features, but keeps multi-tenant SaaS-only
    process.env.LICENSE_ENFORCEMENT = 'off'
    resetConfigCache()
    await expect(requireEntitlement('cis.autofix')).resolves.toBeTruthy()
    await expect(requireEntitlement('tenants.multi_tenant')).rejects.toThrowError(
      EntitlementHttpError,
    )

    // SaaS mode with active enterprise subscription unlocks multi-tenant MSP
    process.env.DEPLOYMENT_MODE = 'saas'
    resetConfigCache()
    await persistLicenseState({
      source: 'stripe',
      tier: 'enterprise',
      licensee: 'SaaS MSP Org',
      updatedBy: 'stripe:webhook',
    })
    await expect(requireEntitlement('tenants.multi_tenant')).resolves.toBeTruthy()
  })

  it('issues and verifies Ed25519-signed offline license keys and rejects tampering', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
      extractable: true,
    })
    const pubPem = await exportSPKI(publicKey)
    const privPem = await exportPKCS8(privateKey)

    const token = await issueSignedLicenseKey(
      {
        tier: 'enterprise',
        licensee: 'MSP Partners LLC',
        maxTenants: 100,
        maxUsers: 25000,
        expiresInDays: 365,
      },
      privPem,
    )

    const verified = await verifySignedLicenseKey(token, pubPem)
    expect(verified.tier).toBe('enterprise')
    expect(verified.licensee).toBe('MSP Partners LLC')
    expect(verified.maxTenants).toBe(100)

    const tampered = `${token.slice(0, -4)}AAAA`
    await expect(verifySignedLicenseKey(tampered, pubPem)).rejects.toThrow()

    await persistLicenseState({
      source: 'license_key',
      tier: verified.tier,
      licensee: verified.licensee,
      rawLicenseKey: token,
      maxTenants: verified.maxTenants,
      maxUsers: verified.maxUsers,
      expiresAt: verified.expiresAt,
      updatedBy: 'owner@msp.com',
    })
    // In self_hosted mode, tier is capped at Pro (single-tenant)
    const selfHostedPlan = await getActivePlan()
    expect(selfHostedPlan.tier).toBe('pro')
    expect(selfHostedPlan.maxTenants).toBe(1)

    // In saas mode, enterprise tier unlocks multi-tenant limits
    process.env.DEPLOYMENT_MODE = 'saas'
    resetConfigCache()
    const saasPlan = await getActivePlan()
    expect(saasPlan.tier).toBe('enterprise')
    expect(saasPlan.maxTenants).toBe(100)
  })

  it('verifies Stripe HMAC-SHA256 webhook signatures and resolves price IDs', () => {
    const secret = 'whsec_test_1234567890'
    const payload = JSON.stringify({ type: 'customer.subscription.updated' })
    const ts = 1_700_000_000
    const sig = crypto
      .createHmac('sha256', secret)
      .update(`${ts}.${payload}`)
      .digest('hex')

    expect(
      verifyStripeWebhookSignature(
        payload,
        `t=${ts},v1=${sig}`,
        secret,
        300,
        ts + 10,
      ).ok,
    ).toBe(true)

    expect(
      verifyStripeWebhookSignature(
        payload,
        `t=${ts},v1=deadbeef`,
        secret,
        300,
        ts + 10,
      ).ok,
    ).toBe(false)

    expect(
      verifyStripeWebhookSignature(
        payload,
        `t=${ts},v1=${sig}`,
        secret,
        300,
        ts + 600,
      ).ok,
    ).toBe(false)

    expect(
      resolveTierFromStripePriceId('price_ent', {
        stripePricePro: 'price_pro',
        stripePriceEnterprise: 'price_ent',
      }),
    ).toBe('enterprise')
  })
})
