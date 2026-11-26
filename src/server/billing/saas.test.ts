import { generateKeyPair, SignJWT } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { verifyEntraIdToken } from '~/server/auth/oidc'
import { resetConfigCache } from '~/server/config'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import {
  createStripeBillingPortalSession,
  createStripeCheckoutSession,
} from './stripe-client'

const CLIENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
const ORG_TENANT_ID = '11111111-2222-3333-4444-555555555555'
const CONSUMER_MSA_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad'

describe('Phase CF-4 SaaS /organizations Multi-Tenant OIDC & Stripe Checkout', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      DEPLOYMENT_MODE: 'saas',
      OIDC_CLIENT_ID: CLIENT_ID,
      OIDC_CLIENT_SECRET: 'saas-oidc-secret',
      SESSION_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
    }
    resetConfigCache()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('verifies organizational multi-tenant Entra ID tokens and rejects personal consumer MSA tokens', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256')

    const validWorkToken = await new SignJWT({
      tid: ORG_TENANT_ID,
      oid: 'saas-user-oid-1',
      preferred_username: 'owner@msp-partner.com',
      name: 'MSP Founder',
      nonce: 'nonce-abc',
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(`https://login.microsoftonline.com/${ORG_TENANT_ID}/v2.0`)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)

    const verified = await verifyEntraIdToken({
      idToken: validWorkToken,
      expectedNonce: 'nonce-abc',
      tenantId: 'organizations',
      clientId: CLIENT_ID,
      multiTenant: true,
      jwks: publicKey,
    })

    expect(verified.tenantId).toBe(ORG_TENANT_ID)
    expect(verified.upn).toBe('owner@msp-partner.com')

    // Reject personal Outlook/Hotmail consumer MSA tenant
    const consumerToken = await new SignJWT({
      tid: CONSUMER_MSA_TENANT_ID,
      oid: 'msa-oid',
      nonce: 'nonce-abc',
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(`https://login.microsoftonline.com/${CONSUMER_MSA_TENANT_ID}/v2.0`)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)

    await expect(
      verifyEntraIdToken({
        idToken: consumerToken,
        expectedNonce: 'nonce-abc',
        tenantId: 'organizations',
        clientId: CLIENT_ID,
        multiTenant: true,
        jwks: publicKey,
      }),
    ).rejects.toThrow(/personal microsoft accounts/i)

    // Reject issuer/tid mismatch spoofing
    const forgedIssuerToken = await new SignJWT({
      tid: ORG_TENANT_ID,
      oid: 'spoof-oid',
      nonce: 'nonce-abc',
    })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(
        'https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0',
      )
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey)

    await expect(
      verifyEntraIdToken({
        idToken: forgedIssuerToken,
        expectedNonce: 'nonce-abc',
        tenantId: 'organizations',
        clientId: CLIENT_ID,
        multiTenant: true,
        jwks: publicKey,
      }),
    ).rejects.toThrow()
  })

  it('creates Stripe Checkout & Billing Portal sessions over pure fetch with org metadata', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: 'cs_test_123',
            url: 'https://checkout.stripe.com/pay/cs_test_123',
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            url: 'https://billing.stripe.com/session/bps_123',
          }),
          { status: 200 },
        ),
      )

    const checkout = await createStripeCheckoutSession(
      {
        secretKey: 'sk_test_123',
        priceId: 'price_saas_monthly',
        organizationId: 'org_abc123',
        customerEmail: 'owner@msp-partner.com',
        successUrl: 'https://app.pocket365.io/billing?checkout=success',
        cancelUrl: 'https://app.pocket365.io/billing?checkout=canceled',
      },
      fetchMock,
    )

    expect(checkout.id).toBe('cs_test_123')
    expect(checkout.url).toContain('checkout.stripe.com')

    const [checkoutUrl, checkoutInit] = fetchMock.mock.calls[0]!
    expect(String(checkoutUrl)).toContain('/v1/checkout/sessions')
    expect(String(checkoutInit?.body)).toContain('client_reference_id=org_abc123')
    expect(String(checkoutInit?.body)).toContain(
      'metadata%5BorganizationId%5D=org_abc123',
    )

    const portal = await createStripeBillingPortalSession(
      {
        secretKey: 'sk_test_123',
        stripeCustomerId: 'cus_999',
        returnUrl: 'https://app.pocket365.io/billing',
      },
      fetchMock,
    )
    expect(portal.url).toContain('billing.stripe.com')
  })
})
