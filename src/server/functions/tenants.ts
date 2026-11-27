import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { and, desc, eq } from 'drizzle-orm'
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
import { enforceRateLimitAsync } from '~/server/security/rate-limit'
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
  const session = await requireSession()
  const [accessible, active, plan] = await Promise.all([
    listAccessibleTenants(session),
    resolveActiveTenantForSession(session),
    getActivePlan(session.organizationId),
  ])
  const db = getDb()

  const accessRules = isAdminRole(session.role)
    ? await db
        .select()
        .from(tenantAccess)
        .where(eq(tenantAccess.organizationId, session.organizationId))
        .orderBy(desc(tenantAccess.createdAt))
        .limit(100)
        .all()
    : []

  return {
    deploymentMode: plan.deploymentMode,
    multiTenantEnabled: plan.multiTenantEnabled,
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
    const session = await requireSession()
    const switched = await setSessionActiveTenant(session, data.managedTenantId)
    await recordAuditLog({
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
    const session = await requireRole('admin', undefined, 'tenant.add')
    await requireEntitlement('tenants.multi_tenant', session)

    const [plan, current] = await Promise.all([
      getActivePlan(session.organizationId),
      listAllManagedTenants(session.organizationId),
    ])
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

    const created = await createManagedTenantRecord({
      organizationId: session.organizationId,
      entraTenantId: data.entraTenantId,
      displayName: data.displayName,
      primaryDomain: data.primaryDomain,
      connectionMode: data.connectionMode,
      clientId: data.clientId,
      clientSecret: data.clientSecret,
      createdBy: session.upn,
    })

    await recordAuditLog({
      organizationId: session.organizationId,
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
    const session = await requireRole('admin', undefined, 'tenant.delete')
    const target = await getManagedTenantById(
      data.managedTenantId,
      session.organizationId,
    )
    if (!target) throw new Error('Managed tenant not found.')
    if (target.isPrimary === 1) {
      throw new Error('Cannot remove the primary environment-configured tenant.')
    }

    const db = getDb()
    await db
      .delete(tenantAccess)
      .where(
        and(
          eq(tenantAccess.managedTenantId, target.id),
          eq(tenantAccess.organizationId, session.organizationId),
        ),
      )
      .run()
    await db
      .delete(managedTenants)
      .where(
        and(
          eq(managedTenants.id, target.id),
          eq(managedTenants.organizationId, session.organizationId),
        ),
      )
      .run()
    evictTenantGraphClient(target.id, session.organizationId)

    await recordAuditLog({
      organizationId: session.organizationId,
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
    const session = await requireRole('admin', undefined, 'tenant.test_connection')
    const target = await getManagedTenantById(
      data.managedTenantId,
      session.organizationId,
    )
    if (!target) throw new Error('Managed tenant not found.')

    const db = getDb()
    const now = Date.now()
    console.info(
      `[Pocket365 Tenant Test] Testing connection for tenant "${target.displayName}" (id: ${target.id}, entraTenantId: ${target.entraTenantId}, mode: ${target.connectionMode}, clientId: "${target.clientId}")`,
    )
    try {
      const client = await getGraphClient(target.id, session.organizationId)
      const org = await client.getOrganization()
      const primaryDomain =
        org?.verifiedDomains.find((d) => d.isDefault)?.name ||
        org?.verifiedDomains[0]?.name ||
        target.primaryDomain

      console.info(
        `[Pocket365 Tenant Test] Successfully connected to tenant "${target.displayName}" (${target.entraTenantId}): verifiedDomain=${primaryDomain}`,
      )

      await db
        .update(managedTenants)
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

      await recordAuditLog({
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
      console.error(
        `[Pocket365 Tenant Test] Connection test failed for tenant "${target.displayName}" (${target.entraTenantId}): ${msg}`,
      )
      await db
        .update(managedTenants)
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
  const session = await requireRole('admin', undefined, 'tenant.generate_consent')
  await requireEntitlement('tenants.multi_tenant', session)
  const { consentUrl } = await createAdminConsentRequestUrl(
    session.upn,
    getRequest(),
    session.organizationId,
  )
  return { consentUrl }
})

export const runCrossTenantPostureScanFn = createServerFn({
  method: 'POST',
}).handler(async () => {
  const session = await requireRole('admin', undefined, 'tenant.cross_posture_scan')
  await requireEntitlement('tenants.multi_tenant', session)
  await enforceRateLimitAsync('heavy', session.oid)

  const tenants = await listAllManagedTenants(session.organizationId)
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
      const client = await getGraphClient(t.id)
      const [cis, mfaRes] = await Promise.all([
        collectCisScan(t.id),
        client
          .listUserRegistrationDetails({ top: 500 })
          .then((r) => summarizeMfaCoverage(r.items).mfaCoveragePct)
          .catch(() => null),
      ])

      await db
        .update(managedTenants)
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
      await db
        .update(managedTenants)
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

  await recordAuditLog({
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
    const session = await requireRole('owner', undefined, 'tenant.grant_access')
    const db = getDb()
    const id = crypto.randomUUID()
    await db
      .insert(tenantAccess)
      .values({
        id,
        organizationId: session.organizationId,
        principal: data.principal.trim().toLowerCase(),
        managedTenantId: data.managedTenantId,
        createdBy: session.upn,
        createdAt: Date.now(),
      })
      .run()

    await recordAuditLog({
      organizationId: session.organizationId,
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
    const session = await requireRole('owner', undefined, 'tenant.revoke_access')
    const db = getDb()
    await db
      .delete(tenantAccess)
      .where(
        and(
          eq(tenantAccess.id, data.id),
          eq(tenantAccess.organizationId, session.organizationId),
        ),
      )
      .run()
    await recordAuditLog({
      organizationId: session.organizationId,
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
