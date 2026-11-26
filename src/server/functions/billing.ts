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
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { getClientIp } from '~/server/http/proxy'

export const getBillingStatusFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    requireSession()
    const cfg = getConfig()
    const plan = getActivePlan()

    return {
      plan,
      catalog: Object.values(TIER_CATALOG),
      stripeConfigured: Boolean(cfg.stripeWebhookSecret),
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
    const session = requireRole('owner', undefined, 'billing.apply_license')
    const cfg = getConfig()
    const claims = await verifySignedLicenseKey(
      data.licenseKey,
      cfg.licensePublicKeyPem,
    )

    persistLicenseState({
      source: 'license_key',
      tier: claims.tier,
      licensee: claims.licensee,
      rawLicenseKey: data.licenseKey,
      maxTenants: claims.maxTenants,
      maxUsers: claims.maxUsers,
      expiresAt: claims.expiresAt,
      updatedBy: session.upn,
    })

    recordAuditLog({
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

    return { ok: true, plan: getActivePlan() }
  })
