/**
 * Pure Web `fetch()` Stripe API client for Cloudflare Workers (zero Node SDK dependencies).
 * Supports Checkout Session creation and Customer Billing Portal sessions.
 */

const STRIPE_API_BASE = 'https://api.stripe.com/v1'

export interface StripeCheckoutSessionResult {
  id: string
  url: string
}

export async function createStripeCheckoutSession(
  params: {
    secretKey: string
    priceId: string
    organizationId: string
    customerEmail: string
    existingCustomerId?: string | null
    successUrl: string
    cancelUrl: string
  },
  fetchImpl: typeof fetch = fetch,
): Promise<StripeCheckoutSessionResult> {
  if (!params.secretKey || !params.priceId) {
    throw new Error(
      'Stripe Checkout is not configured (set STRIPE_SECRET_KEY and STRIPE_PRICE_SAAS).',
    )
  }

  const body = new URLSearchParams({
    mode: 'subscription',
    'line_items[0][price]': params.priceId,
    'line_items[0][quantity]': '1',
    client_reference_id: params.organizationId,
    'metadata[organizationId]': params.organizationId,
    'subscription_data[metadata][organizationId]': params.organizationId,
    success_url: params.successUrl,
    cancel_url: params.cancelUrl,
    allow_promotion_codes: 'true',
  })

  if (params.existingCustomerId) {
    body.set('customer', params.existingCustomerId)
  } else if (params.customerEmail) {
    body.set('customer_email', params.customerEmail)
  }

  const res = await fetchImpl(`${STRIPE_API_BASE}/checkout/sessions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${params.secretKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  })

  const data = (await res.json().catch(() => ({}))) as {
    id?: string
    url?: string
    error?: { message?: string }
  }

  if (!res.ok || !data.id || !data.url) {
    throw new Error(
      data.error?.message ||
        `Stripe Checkout session creation failed (HTTP ${res.status}).`,
    )
  }

  return { id: data.id, url: data.url }
}

export async function createStripeBillingPortalSession(
  params: {
    secretKey: string
    stripeCustomerId: string
    returnUrl: string
  },
  fetchImpl: typeof fetch = fetch,
): Promise<{ url: string }> {
  if (!params.secretKey) {
    throw new Error('Stripe is not configured (missing STRIPE_SECRET_KEY).')
  }
  if (!params.stripeCustomerId) {
    throw new Error('No Stripe customer record found for this organization.')
  }

  const body = new URLSearchParams({
    customer: params.stripeCustomerId,
    return_url: params.returnUrl,
  })

  const res = await fetchImpl(`${STRIPE_API_BASE}/billing_portal/sessions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${params.secretKey}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  })

  const data = (await res.json().catch(() => ({}))) as {
    url?: string
    error?: { message?: string }
  }

  if (!res.ok || !data.url) {
    throw new Error(
      data.error?.message ||
        `Stripe Billing Portal creation failed (HTTP ${res.status}).`,
    )
  }

  return { url: data.url }
}
