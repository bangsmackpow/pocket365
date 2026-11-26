import crypto from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createSession } from '~/server/auth/session'
import { resetConfigCache } from '~/server/config'
import { closeDb, getDb, initDbForTesting } from '~/server/db'
import { tenantAccess } from '~/server/db/schema'
import { GraphTokenProvider } from '~/server/graph/auth'
import { clearAllTenantGraphClients } from '~/server/graph/client'
import { isEncryptedValue } from '~/server/security/crypto'
import {
  canAccessTenant,
  createManagedTenantRecord,
  ensurePrimaryTenantSeeded,
  listAccessibleTenants,
  resolveActiveTenantForSession,
  resolveTenantGraphCredentials,
  setSessionActiveTenant,
} from './registry'

const PRIMARY_TENANT = '11111111-1111-1111-1111-111111111111'
const CUSTOMER_TENANT_A = '22222222-2222-2222-2222-222222222222'
const CUSTOMER_TENANT_B = '33333333-3333-3333-3333-333333333333'

describe('Phase 4 Multi-Tenant Isolation, Encryption & Access Scoping', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      ENTRA_TENANT_ID: PRIMARY_TENANT,
      GRAPH_CLIENT_ID: 'primary-graph-client',
      GRAPH_CLIENT_SECRET: 'primary-graph-secret',
      SESSION_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
    }
    resetConfigCache()
    clearAllTenantGraphClients()
    initDbForTesting(':memory:')
  })

  afterEach(() => {
    clearAllTenantGraphClients()
    closeDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('auto-seeds primary tenant from ENTRA_TENANT_ID and encrypts customer secrets', () => {
    const primary = ensurePrimaryTenantSeeded()
    expect(primary?.entraTenantId).toBe(PRIMARY_TENANT)
    expect(primary?.isPrimary).toBe(1)

    const custA = createManagedTenantRecord({
      entraTenantId: CUSTOMER_TENANT_A,
      displayName: 'Acme Corp',
      primaryDomain: 'acme.com',
      connectionMode: 'app_credentials',
      clientId: 'acme-client-id',
      clientSecret: 'acme-super-secret',
      createdBy: 'owner@msp.com',
    })

    // Stored secret must be AES-256-GCM encrypted in SQLite
    expect(custA.clientSecretEnc).toBeTruthy()
    expect(isEncryptedValue(custA.clientSecretEnc!)).toBe(true)
    expect(custA.clientSecretEnc).not.toContain('acme-super-secret')

    // Decrypted credentials match only Tenant A
    const credsA = resolveTenantGraphCredentials(custA)
    expect(credsA.entraTenantId).toBe(CUSTOMER_TENANT_A)
    expect(credsA.clientId).toBe('acme-client-id')
    expect(credsA.clientSecret).toBe('acme-super-secret')
  })

  it('isolates Graph OAuth tokens strictly per tenant', async () => {
    const custA = createManagedTenantRecord({
      entraTenantId: CUSTOMER_TENANT_A,
      displayName: 'Tenant A',
      connectionMode: 'app_credentials',
      clientId: 'client-a',
      clientSecret: 'secret-a',
      createdBy: 'owner@msp.com',
    })
    const custB = createManagedTenantRecord({
      entraTenantId: CUSTOMER_TENANT_B,
      displayName: 'Tenant B',
      connectionMode: 'app_credentials',
      clientId: 'client-b',
      clientSecret: 'secret-b',
      createdBy: 'owner@msp.com',
    })

    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      const u = String(url)
      if (u.includes(CUSTOMER_TENANT_A)) {
        return new Response(
          JSON.stringify({ access_token: 'token-for-tenant-A', expires_in: 3600 }),
          { status: 200 },
        )
      }
      if (u.includes(CUSTOMER_TENANT_B)) {
        return new Response(
          JSON.stringify({ access_token: 'token-for-tenant-B', expires_in: 3600 }),
          { status: 200 },
        )
      }
      return new Response('unexpected', { status: 400 })
    })

    const providerA = new GraphTokenProvider(
      fetchMock,
      resolveTenantGraphCredentials(custA),
    )
    const providerB = new GraphTokenProvider(
      fetchMock,
      resolveTenantGraphCredentials(custB),
    )

    expect(await providerA.getAccessToken()).toBe('token-for-tenant-A')
    expect(await providerB.getAccessToken()).toBe('token-for-tenant-B')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('enforces per-tenant technician access scoping and active tenant switching', () => {
    ensurePrimaryTenantSeeded()
    const custA = createManagedTenantRecord({
      entraTenantId: CUSTOMER_TENANT_A,
      displayName: 'Tenant A',
      connectionMode: 'admin_consent',
      createdBy: 'owner@msp.com',
    })
    const custB = createManagedTenantRecord({
      entraTenantId: CUSTOMER_TENANT_B,
      displayName: 'Tenant B',
      connectionMode: 'admin_consent',
      createdBy: 'owner@msp.com',
    })

    const { session: techSession } = createSession({
      userOid: 'tech-oid-1',
      userUpn: 'tech@msp.com',
      displayName: 'Tech One',
      role: 'helpdesk',
      groups: [],
    })

    // Grant tech access ONLY to Tenant A
    getDb()
      .insert(tenantAccess)
      .values({
        id: crypto.randomUUID(),
        principal: 'tech@msp.com',
        managedTenantId: custA.id,
        createdBy: 'owner@msp.com',
        createdAt: Date.now(),
      })
      .run()

    const visible = listAccessibleTenants(techSession)
    expect(visible.map((t) => t.id)).toEqual([custA.id])
    expect(canAccessTenant(techSession, custA.id)).toBe(true)
    expect(canAccessTenant(techSession, custB.id)).toBe(false)

    // Switching to Tenant A succeeds; switching to Tenant B is strictly denied
    expect(setSessionActiveTenant(techSession, custA.id).id).toBe(custA.id)
    expect(() => setSessionActiveTenant(techSession, custB.id)).toThrow(
      /Forbidden/i,
    )

    const active = resolveActiveTenantForSession({
      ...techSession,
      activeTenantId: custA.id,
    })
    expect(active?.id).toBe(custA.id)
  })
})
