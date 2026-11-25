import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { recordAuditLog } from '~/server/db/audit'
import { getRuntimeSettings } from '~/server/db/settings'
import { getGraphClient } from '~/server/graph/client'
import { enqueueJob } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'

const listUsersInputSchema = z.object({
  search: z.string().max(120).optional(),
  nextLink: z.string().url().optional(),
  top: z.number().int().min(5).max(100).optional(),
})

export const listUsersFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listUsersInputSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    requireSession()
    const settings = getRuntimeSettings()
    const graph = getGraphClient()

    const [page, skus] = await Promise.all([
      graph.listUsers({
        search: data.search,
        nextLink: data.nextLink,
        top: data.top ?? settings.defaultPageSize,
      }),
      graph.listSubscribedSkus(),
    ])

    return {
      users: page.items,
      nextLink: page.nextLink,
      subscribedSkus: skus,
    }
  })

const getUserDetailSchema = z.object({
  userId: z.string().min(1),
})

export const getUserDetailFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => getUserDetailSchema.parse(input))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()
    const [user, skus] = await Promise.all([
      graph.getUser(data.userId),
      graph.listSubscribedSkus(),
    ])
    return { user, subscribedSkus: skus }
  })

const toggleUserAccountSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  accountEnabled: z.boolean(),
})

export const toggleUserAccountFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => toggleUserAccountSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.toggle_enabled')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.setUserAccountEnabled(data.userId, data.accountEnabled)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.toggle_enabled',
        target: data.userPrincipalName,
        status: 'success',
        details: { userId: data.userId, accountEnabled: data.accountEnabled },
        ipAddress,
      })
      return { ok: true, accountEnabled: data.accountEnabled }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.toggle_enabled',
        target: data.userPrincipalName,
        status: 'failure',
        details: {
          userId: data.userId,
          accountEnabled: data.accountEnabled,
          error: message,
        },
        ipAddress,
      })
      throw err
    }
  })

const updateUserLicensesSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  addSkuIds: z.array(z.string().uuid()),
  removeSkuIds: z.array(z.string().uuid()),
})

export const updateUserLicensesFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => updateUserLicensesSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.update_licenses')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    if (data.addSkuIds.length === 0 && data.removeSkuIds.length === 0) {
      throw new Error('Specify at least one license to assign or remove.')
    }

    const action =
      data.addSkuIds.length > 0 && data.removeSkuIds.length === 0
        ? 'user.assign_license'
        : data.removeSkuIds.length > 0 && data.addSkuIds.length === 0
          ? 'user.remove_license'
          : 'user.update_licenses'

    try {
      const updatedUser = await graph.assignUserLicenses(
        data.userId,
        data.addSkuIds,
        data.removeSkuIds,
      )
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action,
        target: data.userPrincipalName,
        status: 'success',
        details: {
          userId: data.userId,
          addSkuIds: data.addSkuIds,
          removeSkuIds: data.removeSkuIds,
        },
        ipAddress,
      })
      return { ok: true, user: updatedUser }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action,
        target: data.userPrincipalName,
        status: 'failure',
        details: {
          userId: data.userId,
          addSkuIds: data.addSkuIds,
          removeSkuIds: data.removeSkuIds,
          error: message,
        },
        ipAddress,
      })
      throw err
    }
  })

const bulkToggleUsersSchema = z.object({
  userIds: z.array(z.string().min(1)).min(1).max(200),
  accountEnabled: z.boolean(),
})

export const enqueueBulkToggleUsersFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => bulkToggleUsersSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.bulk_toggle_enabled')
    const job = enqueueJob({
      type: 'user.bulk_toggle_enabled',
      payload: {
        userIds: data.userIds,
        accountEnabled: data.accountEnabled,
      },
      actor: { oid: session.oid, upn: session.upn, role: session.role },
      ipAddress: getClientIp(getRequest()),
    })
    return { job }
  })

const bulkAssignLicenseSchema = z.object({
  userIds: z.array(z.string().min(1)).min(1).max(200),
  addSkuIds: z.array(z.string().uuid()),
  removeSkuIds: z.array(z.string().uuid()),
})

export const enqueueBulkAssignLicenseFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => bulkAssignLicenseSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.bulk_assign_license')
    if (data.addSkuIds.length === 0 && data.removeSkuIds.length === 0) {
      throw new Error('Select at least one SKU to assign or remove.')
    }
    const job = enqueueJob({
      type: 'user.bulk_assign_license',
      payload: {
        userIds: data.userIds,
        addSkuIds: data.addSkuIds,
        removeSkuIds: data.removeSkuIds,
      },
      actor: { oid: session.oid, upn: session.upn, role: session.role },
      ipAddress: getClientIp(getRequest()),
    })
    return { job }
  })
