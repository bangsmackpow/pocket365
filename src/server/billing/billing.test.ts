import crypto from 'node:crypto'
import { exportPKCS8, exportSPKI, generateKeyPair } from 'jose'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetConfigCache } from '~/server/config'
import { closeDb, initDbForTesting } from '~/server/db'
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
    initDbForTesting(':memory:')
  })

  afterEach(() => {
    closeDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('enforces tier entitlements strictly when LICENSE_ENFORCEMENT=strict and allows all when off', () => {
    expect(() => requireEntitlement('core.signins')).not.toThrow()
    expect(() => requireEntitlement('cis.autofix')).toThrowError(
      EntitlementHttpError,
    )
    expect(() => requireEntitlement('tenants.multi_tenant')).toThrowError(
      EntitlementHttpError,
    )

    // Upgrade stored plan to pro
    persistLicenseState({
      source: 'license_key',
      tier: 'pro',
      licensee: 'Contoso IT',
      updatedBy: 'admin@contoso.com',
    })
    expect(() => requireEntitlement('cis.autofix')).not.toThrow()
    expect(() => requireEntitlement('tenants.multi_tenant')).toThrowError(
      EntitlementHttpError,
    )

    // Self-hosted open mode (default) allows everything cleanly
    process.env.LICENSE_ENFORCEMENT = 'off'
    resetConfigCache()
    expect(() => requireEntitlement('tenants.multi_tenant')).not.toThrow()
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

    // Tampered token must fail verification
    const tampered = `${token.slice(0, -4)}AAAA`
    await expect(verifySignedLicenseKey(tampered, pubPem)).rejects.toThrow()

    persistLicenseState({
      source: 'license_key',
      tier: verified.tier,
      licensee: verified.licensee,
      rawLicenseKey: token,
      maxTenants: verified.maxTenants,
      maxUsers: verified.maxUsers,
      expiresAt: verified.expiresAt,
      updatedBy: 'owner@msp.com',
    })
    expect(getActivePlan().tier).toBe('enterprise')
    expect(getActivePlan().maxTenants).toBe(100)
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
      verifyStripeWebhookSignature(payload, `t=${ts},v1=${sig}`, secret, 300, ts + 10)
        .ok,
    ).toBe(true)

    expect(
      verifyStripeWebhookSignature(payload, `t=${ts},v1=deadbeef`, secret, 300, ts + 10)
        .ok,
    ).toBe(false)

    // Expired timestamp (>300s) rejected
    expect(
      verifyStripeWebhookSignature(payload, `t=${ts},v1=${sig}`, secret, 300, ts + 600)
        .ok,
    ).toBe(false)

    expect(
      resolveTierFromStripePriceId('price_ent', {
        stripePricePro: 'price_pro',
        stripePriceEnterprise: 'price_ent',
      }),
    ).toBe('enterprise')
  })
})
