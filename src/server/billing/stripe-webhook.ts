import crypto from 'node:crypto'
import type { PlanTier } from '~/server/db/schema'

export function verifyStripeWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
  webhookSecret: string,
  toleranceSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): { ok: boolean; error?: string } {
  if (!webhookSecret) {
    return { ok: false, error: 'STRIPE_WEBHOOK_SECRET is not configured.' }
  }
  if (!signatureHeader) {
    return { ok: false, error: 'Missing Stripe-Signature header.' }
  }

  const parts = signatureHeader.split(',')
  let timestamp = 0
  const signatures: string[] = []

  for (const part of parts) {
    const [k, v] = part.split('=')
    if (k === 't' && v) timestamp = Number.parseInt(v, 10)
    if (k === 'v1' && v) signatures.push(v)
  }

  if (!timestamp || signatures.length === 0) {
    return { ok: false, error: 'Malformed Stripe-Signature header.' }
  }

  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    return { ok: false, error: 'Stripe webhook timestamp outside tolerance window.' }
  }

  const signedPayload = `${timestamp}.${rawBody}`
  const expected = crypto
    .createHmac('sha256', webhookSecret)
    .update(signedPayload, 'utf8')
    .digest('hex')

  const expectedBuf = Buffer.from(expected, 'hex')
  for (const sig of signatures) {
    if (!/^[0-9a-fA-F]+$/.test(sig) || sig.length !== expected.length) continue
    const candidateBuf = Buffer.from(sig, 'hex')
    if (crypto.timingSafeEqual(expectedBuf, candidateBuf)) {
      return { ok: true }
    }
  }

  return { ok: false, error: 'Invalid Stripe webhook signature.' }
}

export function resolveTierFromStripePriceId(
  priceId: string | undefined,
  config: { stripePricePro: string; stripePriceEnterprise: string },
): PlanTier {
  if (priceId && config.stripePriceEnterprise && priceId === config.stripePriceEnterprise) {
    return 'enterprise'
  }
  if (priceId && config.stripePricePro && priceId === config.stripePricePro) {
    return 'pro'
  }
  return 'community'
}
