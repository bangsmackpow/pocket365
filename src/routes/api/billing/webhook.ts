import { createFileRoute } from '@tanstack/react-router'
import { persistLicenseState } from '~/server/billing/entitlements'
import {
  resolveTierFromStripePriceId,
  verifyStripeWebhookSignature,
} from '~/server/billing/stripe-webhook'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { getClientIp } from '~/server/http/proxy'
import {
  DEFAULT_ORG_ID,
  findOrganizationByStripeCustomerId,
  updateOrganizationBilling,
} from '~/server/orgs/service'

interface StripeEventPayload {
  id?: string
  type?: string
  data?: {
    object?: {
      id?: string
      customer?: string
      subscription?: string
      client_reference_id?: string
      status?: string
      current_period_end?: number
      metadata?: {
        organizationId?: string
      }
      items?: {
        data?: Array<{ price?: { id?: string } }>
      }
    }
  }
}

async function resolveWebhookOrganizationId(
  obj: NonNullable<StripeEventPayload['data']>['object'],
): Promise<string> {
  const fromMeta = obj?.metadata?.organizationId?.trim()
  if (fromMeta) return fromMeta
  const fromClientRef = obj?.client_reference_id?.trim()
  if (fromClientRef) return fromClientRef
  if (obj?.customer) {
    const org = await findOrganizationByStripeCustomerId(obj.customer)
    if (org) return org.id
  }
  return DEFAULT_ORG_ID
}

export const Route = createFileRoute('/api/billing/webhook')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const cfg = getConfig()
        const rawBody = await request.text()
        const sigHeader = request.headers.get('stripe-signature')

        const verified = verifyStripeWebhookSignature(
          rawBody,
          sigHeader,
          cfg.stripeWebhookSecret,
        )
        if (!verified.ok) {
          return Response.json(
            { error: 'INVALID_SIGNATURE', message: verified.error },
            { status: 400 },
          )
        }

        let event: StripeEventPayload
        try {
          event = JSON.parse(rawBody) as StripeEventPayload
        } catch {
          return Response.json(
            { error: 'INVALID_JSON', message: 'Invalid JSON payload.' },
            { status: 400 },
          )
        }

        const eventType = event.type || ''
        const obj = event.data?.object
        const ipAddress = getClientIp(request)
        const organizationId = await resolveWebhookOrganizationId(obj)

        if (eventType === 'checkout.session.completed') {
          const tier = cfg.deploymentMode === 'saas' ? 'enterprise' : 'pro'
          await persistLicenseState({
            organizationId,
            source: 'stripe',
            tier,
            licensee: obj?.customer || 'Stripe Subscriber',
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.subscription ?? null,
            updatedBy: 'stripe:checkout',
          })

          await updateOrganizationBilling({
            organizationId,
            planTier: tier,
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.subscription ?? null,
            subscriptionStatus: 'active',
          })

          await recordAuditLog({
            organizationId,
            actorOid: 'stripe',
            actorUpn: 'stripe:webhook',
            actorRole: 'system',
            action: 'billing.checkout_completed',
            target: obj?.subscription || obj?.id || 'checkout',
            status: 'success',
            details: { eventType, tier, organizationId },
            ipAddress,
          })
        } else if (
          eventType === 'customer.subscription.created' ||
          eventType === 'customer.subscription.updated'
        ) {
          const priceId = obj?.items?.data?.[0]?.price?.id
          const isActive =
            obj?.status === 'active' || obj?.status === 'trialing'
          const tier = isActive
            ? cfg.deploymentMode === 'saas'
              ? 'enterprise'
              : resolveTierFromStripePriceId(priceId, cfg)
            : 'community'

          await persistLicenseState({
            organizationId,
            source: 'stripe',
            tier,
            licensee: obj?.customer || 'Stripe Customer',
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.id ?? null,
            expiresAt: obj?.current_period_end
              ? obj.current_period_end * 1000
              : null,
            updatedBy: 'stripe:webhook',
          })

          await updateOrganizationBilling({
            organizationId,
            planTier: tier,
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.id ?? null,
            subscriptionStatus:
              obj?.status === 'trialing'
                ? 'trialing'
                : obj?.status === 'active'
                  ? 'active'
                  : obj?.status === 'past_due'
                    ? 'past_due'
                    : 'canceled',
          })

          await recordAuditLog({
            organizationId,
            actorOid: 'stripe',
            actorUpn: 'stripe:webhook',
            actorRole: 'system',
            action: 'billing.subscription_sync',
            target: obj?.id || 'subscription',
            status: 'success',
            details: { eventType, tier, status: obj?.status, organizationId },
            ipAddress,
          })
        } else if (eventType === 'customer.subscription.deleted') {
          await persistLicenseState({
            organizationId,
            source: 'stripe',
            tier: 'community',
            licensee: obj?.customer || 'Stripe Customer',
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.id ?? null,
            expiresAt: null,
            updatedBy: 'stripe:webhook',
          })

          await updateOrganizationBilling({
            organizationId,
            planTier: 'community',
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.id ?? null,
            subscriptionStatus: 'canceled',
          })

          await recordAuditLog({
            organizationId,
            actorOid: 'stripe',
            actorUpn: 'stripe:webhook',
            actorRole: 'system',
            action: 'billing.subscription_canceled',
            target: obj?.id || 'subscription',
            status: 'success',
            details: { eventType, organizationId },
            ipAddress,
          })
        }

        return Response.json({ received: true })
      },
    },
  },
})
