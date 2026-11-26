import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createSession, listActiveSessions } from '~/server/auth/session'
import {
  EntitlementHttpError,
  getActivePlan,
  persistLicenseState,
  requireEntitlement,
} from '~/server/billing/entitlements'
import { resetConfigCache } from '~/server/config'
import { listAuditLogs, recordAuditLog } from '~/server/db/audit'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import {
  createManagedTenantRecord,
  getManagedTenantById,
  listAllManagedTenants,
  setSessionActiveTenant,
} from '~/server/tenants/registry'
import {
  buildOrgExportKey,
  findOrCreateOrgForEntraTenant,
  isExportKeyOwnedByOrg,
} from './service'

describe('Phase CF-2 DEPLOYMENT_MODE & Multi-Org SaaS Isolation', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      DEPLOYMENT_MODE: 'saas',
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

  it('provisions isolated organizations per Entra home tenant and blocks cross-org access', async () => {
    const { org: orgA, created: createdA } = await findOrCreateOrgForEntraTenant({
      homeEntraTenantId: 'aaaaaaaa-1111-1111-1111-111111111111',
      ownerUpn: 'alice@msp-alpha.com',
    })
    expect(createdA).toBe(true)

    const { org: orgA2, created: createdA2 } = await findOrCreateOrgForEntraTenant({
      homeEntraTenantId: 'aaaaaaaa-1111-1111-1111-111111111111',
      ownerUpn: 'alice@msp-alpha.com',
    })
    expect(createdA2).toBe(false)
    expect(orgA2.id).toBe(orgA.id)

    const { org: orgB } = await findOrCreateOrgForEntraTenant({
      homeEntraTenantId: 'bbbbbbbb-2222-2222-2222-222222222222',
      ownerUpn: 'bob@msp-beta.com',
    })

    // Each org adds its own managed tenant
    const tenantA = await createManagedTenantRecord({
      organizationId: orgA.id,
      entraTenantId: '11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      displayName: 'Alpha Client 1',
      connectionMode: 'admin_consent',
      createdBy: 'alice@msp-alpha.com',
    })
    const tenantB = await createManagedTenantRecord({
      organizationId: orgB.id,
      entraTenantId: '22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
      displayName: 'Beta Client 1',
      connectionMode: 'admin_consent',
      createdBy: 'bob@msp-beta.com',
    })

    // Strict D1 tenant isolation
    expect((await listAllManagedTenants(orgA.id)).map((t) => t.id)).toEqual([
      tenantA.id,
    ])
    expect((await listAllManagedTenants(orgB.id)).map((t) => t.id)).toEqual([
      tenantB.id,
    ])
    expect(await getManagedTenantById(tenantB.id, orgA.id)).toBeNull()

    // Strict session & switching isolation
    const { session: sessA } = await createSession({
      organizationId: orgA.id,
      userOid: 'alice-oid',
      userUpn: 'alice@msp-alpha.com',
      displayName: 'Alice',
      role: 'owner',
      groups: [],
    })
    await createSession({
      organizationId: orgB.id,
      userOid: 'bob-oid',
      userUpn: 'bob@msp-beta.com',
      displayName: 'Bob',
      role: 'owner',
      groups: [],
    })

    expect((await listActiveSessions(orgA.id)).map((s) => s.userUpn)).toEqual([
      'alice@msp-alpha.com',
    ])
    await expect(setSessionActiveTenant(sessA, tenantB.id)).rejects.toThrow(
      /not found/i,
    )

    // Strict audit log isolation
    await recordAuditLog({
      organizationId: orgA.id,
      actorOid: 'alice-oid',
      actorUpn: 'alice@msp-alpha.com',
      actorRole: 'owner',
      action: 'cis.save_snapshot',
      target: 'alpha-target',
      status: 'success',
    })
    await recordAuditLog({
      organizationId: orgB.id,
      actorOid: 'bob-oid',
      actorUpn: 'bob@msp-beta.com',
      actorRole: 'owner',
      action: 'cis.save_snapshot',
      target: 'beta-target',
      status: 'success',
    })
    const logsA = await listAuditLogs({ organizationId: orgA.id })
    expect(logsA.every((l) => l.organizationId === orgA.id)).toBe(true)
    expect(logsA.some((l) => l.target === 'beta-target')).toBe(false)

    // Strict R2 export key isolation
    const r2KeyA = buildOrgExportKey(orgA.id, 'cis', 'report-1.json')
    expect(isExportKeyOwnedByOrg(r2KeyA, orgA.id)).toBe(true)
    expect(isExportKeyOwnedByOrg(r2KeyA, orgB.id)).toBe(false)
    expect(isExportKeyOwnedByOrg(`${r2KeyA}/../${orgB.id}/x`, orgA.id)).toBe(
      false,
    )

    // Per-org SaaS subscription isolation
    await persistLicenseState({
      organizationId: orgA.id,
      source: 'stripe',
      tier: 'enterprise',
      licensee: orgA.name,
      updatedBy: 'stripe:webhook',
    })
    expect((await getActivePlan(orgA.id)).multiTenantEnabled).toBe(true)
    expect((await getActivePlan(orgB.id)).multiTenantEnabled).toBe(false)
    await expect(
      requireEntitlement('tenants.multi_tenant', sessA),
    ).resolves.toBeTruthy()
    await expect(
      requireEntitlement('tenants.multi_tenant', {
        oid: 'bob-oid',
        upn: 'bob@msp-beta.com',
        role: 'owner',
        organizationId: orgB.id,
      }),
    ).rejects.toThrowError(EntitlementHttpError)
  })
})
