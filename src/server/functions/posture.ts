import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { requireEntitlement } from '~/server/billing/entitlements'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { policySnapshots } from '~/server/db/schema'
import {
  getGraphClient,
  type GraphBitlockerRecoveryKey,
  type GraphConditionalAccessPolicy,
  type GraphManagedDevice,
  type GraphRiskyUser,
  type GraphSecureScore,
  type GraphSecurityAlert,
} from '~/server/graph/client'
import {
  diffConditionalAccessSnapshots,
  type CaDriftSummary,
} from '~/server/graph/insights-helpers'
import {
  classifyGraphError,
  type FriendlyGraphError,
} from '~/server/graph/signin-errors'
import { getClientIp } from '~/server/http/proxy'

export const getSecureScoreAndAlertsFn = createServerFn({
  method: 'GET',
}).handler(async () => {
  await requireSession()
  const graph = await getGraphClient()

  const [scoreOutcome, alertsOutcome] = await Promise.all([
    graph
      .getLatestSecureScore()
      .then((s) => ({
        secureScore: s as GraphSecureScore | null,
        error: null as FriendlyGraphError | null,
      }))
      .catch((err) => ({
        secureScore: null as GraphSecureScore | null,
        error: classifyGraphError(err, ['SecurityEvents.Read.All']) as FriendlyGraphError | null,
      })),
    graph
      .listSecurityAlerts(50)
      .then((a) => ({
        alerts: a as GraphSecurityAlert[],
        error: null as FriendlyGraphError | null,
      }))
      .catch((err) => ({
        alerts: [] as GraphSecurityAlert[],
        error: classifyGraphError(err, [
          'SecurityAlert.Read.All',
          'SecurityEvents.Read.All',
        ]) as FriendlyGraphError | null,
      })),
  ])

  return {
    secureScore: scoreOutcome.secureScore,
    scoreError: scoreOutcome.error,
    alerts: alertsOutcome.alerts,
    alertsError: alertsOutcome.error,
  }
})

export interface SerializableCaPolicy {
  id: string
  displayName: string
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced'
  createdDateTime: string | null
  modifiedDateTime: string | null
  grantControls: {
    operator?: string
    builtInControls?: string[]
  } | null
}

export const getConditionalAccessDataFn = createServerFn({
  method: 'GET',
}).handler(async () => {
  await requireSession()
  const db = getDb()
  const graph = await getGraphClient()

  const [snapshots, latestSnapshotRow] = await Promise.all([
    db
      .select({
        id: policySnapshots.id,
        label: policySnapshots.label,
        actorUpn: policySnapshots.actorUpn,
        policyCount: policySnapshots.policyCount,
        createdAt: policySnapshots.createdAt,
      })
      .from(policySnapshots)
      .where(eq(policySnapshots.snapshotType, 'conditional_access'))
      .orderBy(desc(policySnapshots.createdAt))
      .limit(20)
      .all(),
    db
      .select()
      .from(policySnapshots)
      .where(eq(policySnapshots.snapshotType, 'conditional_access'))
      .orderBy(desc(policySnapshots.createdAt))
      .limit(1)
      .get(),
  ])

  try {
    const rawPolicies = await graph.listConditionalAccessPoliciesFull()
    let drift: CaDriftSummary | null = null
    if (latestSnapshotRow) {
      const baseline = JSON.parse(
        latestSnapshotRow.payloadJson,
      ) as GraphConditionalAccessPolicy[]
      drift = diffConditionalAccessSnapshots(baseline, rawPolicies)
    }

    const policies: SerializableCaPolicy[] = rawPolicies.map((p) => ({
      id: p.id,
      displayName: p.displayName,
      state: p.state,
      createdDateTime: p.createdDateTime ?? null,
      modifiedDateTime: p.modifiedDateTime ?? null,
      grantControls: p.grantControls ?? null,
    }))

    return {
      ok: true as const,
      policies,
      snapshots,
      latestSnapshotLabel: latestSnapshotRow?.label ?? null,
      drift,
      error: null as FriendlyGraphError | null,
    }
  } catch (err) {
    return {
      ok: false as const,
      policies: [] as SerializableCaPolicy[],
      snapshots,
      latestSnapshotLabel: latestSnapshotRow?.label ?? null,
      drift: null as CaDriftSummary | null,
      error: classifyGraphError(err, ['Policy.ReadWrite.ConditionalAccess']),
    }
  }
})

const createCaSnapshotSchema = z.object({
  label: z.string().min(1).max(120),
})

export const createCaSnapshotFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => createCaSnapshotSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'ca.create_snapshot')
    await requireEntitlement('posture.ca_drift', session)
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()
    const policies = await graph.listConditionalAccessPoliciesFull()

    const db = getDb()
    const id = crypto.randomUUID()
    const now = Date.now()
    await db
      .insert(policySnapshots)
      .values({
        id,
        snapshotType: 'conditional_access',
        label: data.label.trim(),
        actorUpn: session.upn,
        policyCount: policies.length,
        payloadJson: JSON.stringify(policies),
        createdAt: now,
      })
      .run()

    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'ca.create_snapshot',
      target: data.label.trim(),
      status: 'success',
      details: { snapshotId: id, policyCount: policies.length },
      ipAddress,
    })

    return { ok: true, id, policyCount: policies.length }
  })

const toggleCaPolicySchema = z.object({
  policyId: z.string().min(1),
  displayName: z.string().min(1),
  state: z.enum(['enabled', 'disabled', 'enabledForReportingButNotEnforced']),
})

export const setCaPolicyStateFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => toggleCaPolicySchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'ca.update_state')
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      await graph.setConditionalAccessPolicyState(data.policyId, data.state)
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'ca.update_state',
        target: data.displayName,
        status: 'success',
        details: { policyId: data.policyId, state: data.state },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'ca.update_state',
        target: data.displayName,
        status: 'failure',
        details: {
          policyId: data.policyId,
          state: data.state,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

export const getDevicesAndBitlockerFn = createServerFn({
  method: 'GET',
}).handler(async () => {
  await requireSession()
  const graph = await getGraphClient()

  const [devicesOutcome, bitlockerOutcome] = await Promise.all([
    graph
      .listManagedDevices(100)
      .then((d) => ({
        devices: d as GraphManagedDevice[],
        error: null as FriendlyGraphError | null,
      }))
      .catch((err) => ({
        devices: [] as GraphManagedDevice[],
        error: classifyGraphError(err, [
          'DeviceManagementManagedDevices.ReadWrite.All',
        ]) as FriendlyGraphError | null,
      })),
    graph
      .listBitlockerRecoveryKeys(100)
      .then((k) => ({
        bitlockerKeys: k as GraphBitlockerRecoveryKey[],
        error: null as FriendlyGraphError | null,
      }))
      .catch((err) => ({
        bitlockerKeys: [] as GraphBitlockerRecoveryKey[],
        error: classifyGraphError(err, ['BitlockerKey.Read.All']) as FriendlyGraphError | null,
      })),
  ])

  return {
    devices: devicesOutcome.devices,
    devicesError: devicesOutcome.error,
    bitlockerKeys: bitlockerOutcome.bitlockerKeys,
    bitlockerError: bitlockerOutcome.error,
  }
})

const deviceActionSchema = z.object({
  deviceId: z.string().min(1),
  deviceName: z.string().min(1),
  action: z.enum(['sync', 'remote_lock']),
})

export const runDeviceActionFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => deviceActionSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, `device.${data.action}`)
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      if (data.action === 'sync') {
        await graph.syncManagedDevice(data.deviceId)
      } else {
        await graph.remoteLockManagedDevice(data.deviceId)
      }
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `device.${data.action}`,
        target: data.deviceName,
        status: 'success',
        details: { deviceId: data.deviceId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `device.${data.action}`,
        target: data.deviceName,
        status: 'failure',
        details: {
          deviceId: data.deviceId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

const revealBitlockerSchema = z.object({
  keyId: z.string().min(1),
  deviceId: z.string().nullable().optional(),
})

export const revealBitlockerKeyFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => revealBitlockerSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'bitlocker.reveal_key')
    await requireEntitlement('posture.devices_bitlocker', session)
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      const recoveryKey = await graph.getBitlockerRecoveryKeyValue(data.keyId)
      // Strictly audit access without storing the recovery key itself in D1
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'bitlocker.reveal_key',
        target: data.deviceId || data.keyId,
        status: 'success',
        details: { keyId: data.keyId, deviceId: data.deviceId ?? null },
        ipAddress,
      })
      return { ok: true, key: recoveryKey }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'bitlocker.reveal_key',
        target: data.deviceId || data.keyId,
        status: 'failure',
        details: {
          keyId: data.keyId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

export const listRiskyUsersFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    await requireSession()
    const graph = await getGraphClient()
    try {
      const users = await graph.listRiskyUsers(100)
      return {
        ok: true as const,
        users,
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        users: [] as GraphRiskyUser[],
        error: classifyGraphError(err, ['IdentityRiskyUser.ReadWrite.All']),
      }
    }
  },
)

const riskyUserActionSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  action: z.enum(['confirm_compromised', 'dismiss']),
})

export const runRiskyUserActionFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => riskyUserActionSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, `risky_user.${data.action}`)
    const ipAddress = getClientIp(getRequest())
    const graph = await getGraphClient()

    try {
      if (data.action === 'confirm_compromised') {
        await graph.confirmRiskyUserCompromised(data.userId)
      } else {
        await graph.dismissRiskyUser(data.userId)
      }
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `risky_user.${data.action}`,
        target: data.userPrincipalName,
        status: 'success',
        details: { userId: data.userId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      await recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: `risky_user.${data.action}`,
        target: data.userPrincipalName,
        status: 'failure',
        details: {
          userId: data.userId,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })
