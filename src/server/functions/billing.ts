import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import {
  getActivePlan,
  persistLicenseState,
  TIER_CATALOG,
  verifySignedLicenseKey,
} from '~/server/billing/entitlements'
import {
  createStripeBillingPortalSession,
  createStripeCheckoutSession,
} from '~/server/billing/stripe-client'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { buildCanonicalUrl, getClientIp } from '~/server/http/proxy'
import { getOrganizationById } from '~/server/orgs/service'

export const getBillingStatusFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    const session = await requireSession()
    const cfg = getConfig()
    const [plan, org] = await Promise.all([
      getActivePlan(session.organizationId),
      getOrganizationById(session.organizationId),
    ])

    return {
      deploymentMode: cfg.deploymentMode,
      plan,
      organization: org
        ? {
            id: org.id,
            name: org.name,
            subscriptionStatus: org.subscriptionStatus,
            hasStripeCustomer: Boolean(org.stripeCustomerId),
          }
        : null,
      catalog: Object.values(TIER_CATALOG),
      stripeConfigured: Boolean(cfg.stripeWebhookSecret),
      stripeCheckoutConfigured: Boolean(
        cfg.stripeSecretKey && cfg.stripePriceSaas,
      ),
      licensePublicKeyConfigured: Boolean(cfg.licensePublicKeyPem),
    }
  },
)

const applyLicenseKeySchema = z.object({
  licenseKey: z.string().min(20).max(4096),
})

export const applyLicenseKeyFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => applyLicenseKeySchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('owner', undefined, 'billing.apply_license')
    const cfg = getConfig()
    const claims = await verifySignedLicenseKey(
      data.licenseKey,
      cfg.licensePublicKeyPem,
    )

    await persistLicenseState({
      organizationId: session.organizationId,
      source: 'license_key',
      tier: claims.tier,
      licensee: claims.licensee,
      rawLicenseKey: data.licenseKey,
      maxTenants: claims.maxTenants,
      maxUsers: claims.maxUsers,
      expiresAt: claims.expiresAt,
      updatedBy: session.upn,
    })

    await recordAuditLog({
      organizationId: session.organizationId,
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'billing.apply_license',
      target: claims.licensee,
      status: 'success',
      details: {
        tier: claims.tier,
        maxTenants: claims.maxTenants,
        maxUsers: claims.maxUsers,
        expiresAt: new Date(claims.expiresAt).toISOString(),
      },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, plan: await getActivePlan(session.organizationId) }
  })

export const startSaasCheckoutFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const req = getRequest()
    const session = await requireRole('owner', req, 'billing.start_checkout')
    const cfg = getConfig()
    const org = await getOrganizationById(session.organizationId)

    const checkout = await createStripeCheckoutSession({
      secretKey: cfg.stripeSecretKey,
      priceId: cfg.stripePriceSaas,
      organizationId: session.organizationId,
      customerEmail: session.upn,
      existingCustomerId: org?.stripeCustomerId ?? null,
      successUrl: buildCanonicalUrl('/billing?checkout=success', req),
      cancelUrl: buildCanonicalUrl('/billing?checkout=canceled', req),
    })

    await recordAuditLog({
      organizationId: session.organizationId,
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'billing.checkout_started',
      target: checkout.id,
      status: 'success',
      details: { organizationId: session.organizationId },
      ipAddress: getClientIp(req),
    })

    return { url: checkout.url }
  },
)

export const openStripePortalFn = createServerFn({ method: 'POST' }).handler(
  async () => {
    const req = getRequest()
    const session = await requireRole('owner', req, 'billing.open_portal')
    const cfg = getConfig()
    const org = await getOrganizationById(session.organizationId)

    if (!org?.stripeCustomerId) {
      throw new Error(
        'No active Stripe billing profile found for your organization yet.',
      )
    }

    const portal = await createStripeBillingPortalSession({
      secretKey: cfg.stripeSecretKey,
      stripeCustomerId: org.stripeCustomerId,
      returnUrl: buildCanonicalUrl('/billing', req),
    })

    return { url: portal.url }
  },
)
