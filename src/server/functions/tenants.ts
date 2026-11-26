import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { isAdminRole } from '~/server/auth/roles'
import {
  getActivePlan,
  requireEntitlement,
} from '~/server/billing/entitlements'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { managedTenants, tenantAccess } from '~/server/db/schema'
import { collectCisScan } from '~/server/graph/cis-scanner'
import { evictTenantGraphClient, getGraphClient } from '~/server/graph/client'
import { summarizeMfaCoverage } from '~/server/graph/mfa-helpers'
import { getClientIp } from '~/server/http/proxy'
import { enforceRateLimit } from '~/server/security/rate-limit'
import {
  createAdminConsentRequestUrl,
  createManagedTenantRecord,
  getManagedTenantById,
  listAccessibleTenants,
  listAllManagedTenants,
  resolveActiveTenantForSession,
  setSessionActiveTenant,
} from '~/server/tenants/registry'

export const getTenantsCommandCenterFn = createServerFn({
  method: 'GET',
}).handler(async () => {
  const session = requireSession()
  const accessible = listAccessibleTenants(session)
  const active = resolveActiveTenantForSession(session)
  const plan = getActivePlan()
  const db = getDb()

  const accessRules = isAdminRole(session.role)
    ? db
        .select()
        .from(tenantAccess)
        .orderBy(desc(tenantAccess.createdAt))
        .limit(100)
        .all()
    : []

  return {
    activeTenantId: active?.id ?? null,
    plan: {
      tier: plan.tier,
      enforcement: plan.enforcement,
      maxTenants: plan.maxTenants,
    },
    tenants: accessible.map((t) => ({
      id: t.id,
      entraTenantId: t.entraTenantId,
      displayName: t.displayName,
      primaryDomain: t.primaryDomain,
      connectionMode: t.connectionMode,
      clientId: t.clientId,
      isPrimary: t.isPrimary === 1,
      status: t.status,
      lastHealthCheckAt: t.lastHealthCheckAt,
      lastHealthError: t.lastHealthError,
      lastCisScorePct: t.lastCisScorePct,
      lastMfaCoveragePct: t.lastMfaCoveragePct,
      createdBy: t.createdBy,
      createdAt: t.createdAt,
    })),
    accessRules,
  }
})

const switchTenantSchema = z.object({
  managedTenantId: z.string().uuid(),
})

export const switchActiveTenantFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => switchTenantSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireSession()
    const switched = setSessionActiveTenant(session, data.managedTenantId)
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'tenant.switch',
      target: switched.displayName,
      status: 'success',
      details: {
        managedTenantId: switched.id,
        entraTenantId: switched.entraTenantId,
      },
      ipAddress: getClientIp(getRequest()),
    })
    return {
      ok: true,
      activeTenant: {
        id: switched.id,
        displayName: switched.displayName,
        primaryDomain: switched.primaryDomain,
      },
    }
  })

const addTenantSchema = z.object({
  entraTenantId: z.string().uuid('Must be a valid Entra Tenant GUID'),
  displayName: z.string().min(2).max(120),
  primaryDomain: z.string().max(120).optional(),
  connectionMode: z.enum(['admin_consent', 'app_credentials']),
  clientId: z.string().max(120).optional(),
  clientSecret: z.string().max(512).optional(),
})

export const addManagedTenantFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => addTenantSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'tenant.add')
    requireEntitlement('tenants.multi_tenant', session)

    const plan = getActivePlan()
    const current = listAllManagedTenants()
    if (plan.enforcement === 'strict' && current.length >= plan.maxTenants) {
      throw new Error(
        `Managed tenant limit reached (${plan.maxTenants} max on ${plan.tier} plan).`,
      )
    }

    if (
      data.connectionMode === 'app_credentials' &&
      (!data.clientId?.trim() || !data.clientSecret?.trim())
    ) {
      throw new Error(
        'Client ID and Client Secret are required for dedicated app credentials mode.',
      )
    }

    const created = createManagedTenantRecord({
      entraTenantId: data.entraTenantId,
      displayName: data.displayName,
      primaryDomain: data.primaryDomain,
      connectionMode: data.connectionMode,
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      createdBy: session.upn,
    })

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'tenant.add',
      target: created.displayName,
      status: 'success',
      details: {
        managedTenantId: created.id,
        entraTenantId: created.entraTenantId,
        connectionMode: created.connectionMode,
      },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, id: created.id }
  })

const tenantIdSchema = z.object({
  managedTenantId: z.string().uuid(),
})

export const deleteManagedTenantFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => tenantIdSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'tenant.delete')
    const target = getManagedTenantById(data.managedTenantId)
    if (!target) throw new Error('Managed tenant not found.')
    if (target.isPrimary === 1) {
      throw new Error('Cannot remove the primary environment-configured tenant.')
    }

    const db = getDb()
    db.delete(tenantAccess)
      .where(eq(tenantAccess.managedTenantId, target.id))
      .run()
    db.delete(managedTenants).where(eq(managedTenants.id, target.id)).run()
    evictTenantGraphClient(target.id)

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'tenant.delete',
      target: target.displayName,
      status: 'success',
      details: { entraTenantId: target.entraTenantId },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

export const testTenantConnectionFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => tenantIdSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'tenant.test_connection')
    const target = getManagedTenantById(data.managedTenantId)
    if (!target) throw new Error('Managed tenant not found.')

    const db = getDb()
    const now = Date.now()
    try {
      const client = getGraphClient(target.id)
      const org = await client.getOrganization()
      const primaryDomain =
        org?.verifiedDomains.find((d) => d.isDefault)?.name ||
        org?.verifiedDomains[0]?.name ||
        target.primaryDomain

      db.update(managedTenants)
        .set({
          displayName: org?.displayName || target.displayName,
          primaryDomain,
          status: 'active',
          lastHealthCheckAt: now,
          lastHealthError: null,
          updatedAt: now,
        })
        .where(eq(managedTenants.id, target.id))
        .run()

      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'tenant.test_connection',
        target: org?.displayName || target.displayName,
        status: 'success',
        details: { managedTenantId: target.id, primaryDomain },
        ipAddress: getClientIp(getRequest()),
      })

      return {
        ok: true,
        displayName: org?.displayName || target.displayName,
        primaryDomain,
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      db.update(managedTenants)
        .set({
          status: 'error',
          lastHealthCheckAt: now,
          lastHealthError: msg,
          updatedAt: now,
        })
        .where(eq(managedTenants.id, target.id))
        .run()
      throw err
    }
  })

export const generateAdminConsentLinkFn = createServerFn({
  method: 'POST',
}).handler(async () => {
  const session = requireRole('admin', undefined, 'tenant.generate_consent')
  requireEntitlement('tenants.multi_tenant', session)
  const { consentUrl } = createAdminConsentRequestUrl(session.upn, getRequest())
  return { consentUrl }
})

export const runCrossTenantPostureScanFn = createServerFn({
  method: 'POST',
}).handler(async () => {
  const session = requireRole('admin', undefined, 'tenant.cross_posture_scan')
  requireEntitlement('tenants.multi_tenant', session)
  enforceRateLimit('heavy', session.oid)

  const tenants = listAllManagedTenants()
  const db = getDb()
  const results: Array<{
    tenantId: string
    displayName: string
    cisScorePct: number | null
    mfaCoveragePct: number | null
    error: string | null
  }> = []

  for (const t of tenants) {
    const now = Date.now()
    try {
      const [cis, mfaRes] = await Promise.all([
        collectCisScan(t.id),
        getGraphClient(t.id)
          .listUserRegistrationDetails({ top: 500 })
          .then((r) => summarizeMfaCoverage(r.items).mfaCoveragePct)
          .catch(() => null),
      ])

      db.update(managedTenants)
        .set({
          lastCisScorePct: cis.summary.scorePct,
          lastMfaCoveragePct: mfaRes,
          lastHealthCheckAt: now,
          lastHealthError: null,
          status: 'active',
          updatedAt: now,
        })
        .where(eq(managedTenants.id, t.id))
        .run()

      results.push({
        tenantId: t.id,
        displayName: t.displayName,
        cisScorePct: cis.summary.scorePct,
        mfaCoveragePct: mfaRes,
        error: null,
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      db.update(managedTenants)
        .set({
          lastHealthCheckAt: now,
          lastHealthError: msg,
          status: 'error',
          updatedAt: now,
        })
        .where(eq(managedTenants.id, t.id))
        .run()
      results.push({
        tenantId: t.id,
        displayName: t.displayName,
        cisScorePct: null,
        mfaCoveragePct: null,
        error: msg,
      })
    }
  }

  recordAuditLog({
    actorOid: session.oid,
    actorUpn: session.upn,
    actorRole: session.role,
    action: 'tenant.cross_posture_scan',
    target: `${tenants.length} tenant(s)`,
    status: 'success',
    details: { scanned: results.length },
    ipAddress: getClientIp(getRequest()),
  })

  return { ok: true, results }
})

const grantAccessSchema = z.object({
  principal: z.string().min(3).max(180),
  managedTenantId: z.string().uuid(),
})

export const grantTenantAccessFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => grantAccessSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('owner', undefined, 'tenant.grant_access')
    const db = getDb()
    const id = crypto.randomUUID()
    db.insert(tenantAccess)
      .values({
        id,
        principal: data.principal.trim().toLowerCase(),
        managedTenantId: data.managedTenantId,
        createdBy: session.upn,
        createdAt: Date.now(),
      })
      .run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'tenant.grant_access',
      target: data.principal.trim().toLowerCase(),
      status: 'success',
      details: { managedTenantId: data.managedTenantId },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, id }
  })

const revokeAccessSchema = z.object({
  id: z.string().uuid(),
})

export const revokeTenantAccessFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => revokeAccessSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('owner', undefined, 'tenant.revoke_access')
    const db = getDb()
    db.delete(tenantAccess).where(eq(tenantAccess.id, data.id)).run()
    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'tenant.revoke_access',
      target: data.id,
      status: 'success',
      details: {},
      ipAddress: getClientIp(getRequest()),
    })
    return { ok: true }
  })
