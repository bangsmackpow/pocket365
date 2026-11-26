import { createFileRoute } from '@tanstack/react-router'
import { persistLicenseState } from '~/server/billing/entitlements'
import {
  resolveTierFromStripePriceId,
  verifyStripeWebhookSignature,
} from '~/server/billing/stripe-webhook'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { getClientIp } from '~/server/http/proxy'

interface StripeEventPayload {
  id?: string
  type?: string
  data?: {
    object?: {
      id?: string
      customer?: string
      status?: string
      current_period_end?: number
      items?: {
        data?: Array<{ price?: { id?: string } }>
      }
    }
  }
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

        if (
          eventType === 'customer.subscription.created' ||
          eventType === 'customer.subscription.updated'
        ) {
          const priceId = obj?.items?.data?.[0]?.price?.id
          const isActive =
            obj?.status === 'active' || obj?.status === 'trialing'
          const tier = isActive
            ? resolveTierFromStripePriceId(priceId, cfg)
            : 'community'

          persistLicenseState({
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

          recordAuditLog({
            actorOid: 'stripe',
            actorUpn: 'stripe:webhook',
            actorRole: 'system',
            action: 'billing.subscription_sync',
            target: obj?.id || 'subscription',
            status: 'success',
            details: { eventType, tier, status: obj?.status },
            ipAddress,
          })
        } else if (eventType === 'customer.subscription.deleted') {
          persistLicenseState({
            source: 'stripe',
            tier: 'community',
            licensee: obj?.customer || 'Stripe Customer',
            stripeCustomerId: obj?.customer ?? null,
            stripeSubscriptionId: obj?.id ?? null,
            expiresAt: null,
            updatedBy: 'stripe:webhook',
          })

          recordAuditLog({
            actorOid: 'stripe',
            actorUpn: 'stripe:webhook',
            actorRole: 'system',
            action: 'billing.subscription_canceled',
            target: obj?.id || 'subscription',
            status: 'success',
            details: { eventType },
            ipAddress,
          })
        }

        return Response.json({ received: true })
      },
    },
  },
})
