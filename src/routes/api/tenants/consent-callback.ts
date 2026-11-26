import { createFileRoute } from '@tanstack/react-router'
import { eq } from 'drizzle-orm'
import { guardApiRole } from '~/server/auth/guards'
import { getActivePlan, requireEntitlement } from '~/server/billing/entitlements'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { managedTenants, oidcStates } from '~/server/db/schema'
import { getGraphClient } from '~/server/graph/client'
import { buildCanonicalUrl, getClientIp } from '~/server/http/proxy'
import {
  createManagedTenantRecord,
  listAllManagedTenants,
} from '~/server/tenants/registry'

export const Route = createFileRoute('/api/tenants/consent-callback')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = guardApiRole('admin', request, 'tenant.consent_callback')
        if (!auth.ok) {
          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl('/login?returnTo=/tenants', request),
            },
          })
        }

        const url = new URL(request.url)
        const errorParam = url.searchParams.get('error')
        const errorDesc = url.searchParams.get('error_description')
        const state = url.searchParams.get('state') || ''
        const entraTenantId = url.searchParams.get('tenant') || ''
        const adminConsent = url.searchParams.get('admin_consent') === 'True'

        if (errorParam || !adminConsent || !entraTenantId || !state) {
          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl(
                `/tenants?error=${encodeURIComponent(errorDesc || errorParam || 'Admin consent was not granted.')}`,
                request,
              ),
            },
          })
        }

        const db = getDb()
        const tx = db
          .select()
          .from(oidcStates)
          .where(eq(oidcStates.state, state))
          .get()
        if (tx) {
          db.delete(oidcStates).where(eq(oidcStates.state, state)).run()
        }
        if (!tx || tx.codeVerifier !== 'admin_consent' || tx.expiresAt < Date.now()) {
          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl(
                '/tenants?error=Invalid+or+expired+admin+consent+state.',
                request,
              ),
            },
          })
        }

        try {
          requireEntitlement('tenants.multi_tenant', auth.session)
          const plan = getActivePlan()
          const existingList = listAllManagedTenants()
          const already = existingList.find(
            (t) => t.entraTenantId.toLowerCase() === entraTenantId.toLowerCase(),
          )

          let record = already
          if (!record) {
            if (
              plan.enforcement === 'strict' &&
              existingList.length >= plan.maxTenants
            ) {
              throw new Error(
                `Tenant quota reached (${plan.maxTenants} max on ${plan.tier} plan).`,
              )
            }
            record = createManagedTenantRecord({
              entraTenantId,
              displayName: `Tenant ${entraTenantId.slice(0, 8)}`,
              connectionMode: 'admin_consent',
              createdBy: auth.session.upn,
            })
          }

          // Probe Microsoft Graph /organization to auto-populate tenant display name & primary domain
          try {
            const client = getGraphClient(record.id)
            const org = await client.getOrganization()
            if (org) {
              const primaryDomain =
                org.verifiedDomains.find((d) => d.isDefault)?.name ||
                org.verifiedDomains[0]?.name ||
                ''
              db.update(managedTenants)
                .set({
                  displayName: org.displayName || record.displayName,
                  primaryDomain,
                  status: 'active',
                  lastHealthCheckAt: Date.now(),
                  lastHealthError: null,
                  updatedAt: Date.now(),
                })
                .where(eq(managedTenants.id, record.id))
                .run()
            }
          } catch (probeErr) {
            db.update(managedTenants)
              .set({
                lastHealthCheckAt: Date.now(),
                lastHealthError:
                  probeErr instanceof Error
                    ? probeErr.message
                    : String(probeErr),
                updatedAt: Date.now(),
              })
              .where(eq(managedTenants.id, record.id))
              .run()
          }

          recordAuditLog({
            actorOid: auth.session.oid,
            actorUpn: auth.session.upn,
            actorRole: auth.session.role,
            action: 'tenant.onboard_consent',
            target: entraTenantId,
            status: 'success',
            details: { managedTenantId: record.id },
            ipAddress: getClientIp(request),
          })

          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl('/tenants?onboarded=1', request),
            },
          })
        } catch (err) {
          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl(
                `/tenants?error=${encodeURIComponent(err instanceof Error ? err.message : String(err))}`,
                request,
              ),
            },
          })
        }
      },
    },
  },
})
