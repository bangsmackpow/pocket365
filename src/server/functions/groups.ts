import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { recordAuditLog } from '~/server/db/audit'
import { getRuntimeSettings } from '~/server/db/settings'
import { getGraphClient } from '~/server/graph/client'
import { enqueueJob } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'

const listGroupsSchema = z.object({
  search: z.string().max(120).optional(),
  nextLink: z.string().url().optional(),
  top: z.number().int().min(5).max(100).optional(),
})

export const listGroupsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listGroupsSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    requireSession()
    const settings = getRuntimeSettings()
    const graph = getGraphClient()
    const page = await graph.listGroups({
      search: data.search,
      nextLink: data.nextLink,
      top: data.top ?? settings.defaultPageSize,
    })
    return {
      groups: page.items,
      nextLink: page.nextLink,
    }
  })

const groupDetailSchema = z.object({
  groupId: z.string().min(1),
})

export const getGroupDetailFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => groupDetailSchema.parse(input))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()
    const [group, members] = await Promise.all([
      graph.getGroup(data.groupId),
      graph.listGroupMembers(data.groupId),
    ])
    return { group, members }
  })

const searchDirectoryUsersSchema = z.object({
  query: z.string().min(1).max(120),
})

export const searchDirectoryUsersFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => searchDirectoryUsersSchema.parse(input))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()
    const page = await graph.listUsers({ search: data.query, top: 10 })
    return { users: page.items }
  })

const modifyGroupMemberSchema = z.object({
  groupId: z.string().min(1),
  groupDisplayName: z.string().min(1),
  memberId: z.string().min(1),
  memberLabel: z.string().min(1),
})

export const addGroupMemberFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => modifyGroupMemberSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'group.add_member')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.addGroupMember(data.groupId, data.memberId)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'group.add_member',
        target: `${data.groupDisplayName} <- ${data.memberLabel}`,
        status: 'success',
        details: { groupId: data.groupId, memberId: data.memberId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'group.add_member',
        target: `${data.groupDisplayName} <- ${data.memberLabel}`,
        status: 'failure',
        details: {
          groupId: data.groupId,
          memberId: data.memberId,
          error: message,
        },
        ipAddress,
      })
      throw err
    }
  })

export const removeGroupMemberFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => modifyGroupMemberSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'group.remove_member')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.removeGroupMember(data.groupId, data.memberId)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'group.remove_member',
        target: `${data.groupDisplayName} -/-> ${data.memberLabel}`,
        status: 'success',
        details: { groupId: data.groupId, memberId: data.memberId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'group.remove_member',
        target: `${data.groupDisplayName} -/-> ${data.memberLabel}`,
        status: 'failure',
        details: {
          groupId: data.groupId,
          memberId: data.memberId,
          error: message,
        },
        ipAddress,
      })
      throw err
    }
  })

const bulkGroupMembersSchema = z.object({
  groupId: z.string().min(1),
  userIds: z.array(z.string().min(1)).min(1).max(200),
  operation: z.enum(['add', 'remove']),
})

export const enqueueBulkGroupMembersFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => bulkGroupMembersSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'group.bulk_members')
    const job = enqueueJob({
      type:
        data.operation === 'add'
          ? 'group.bulk_add_members'
          : 'group.bulk_remove_members',
      payload: {
        groupId: data.groupId,
        userIds: data.userIds,
      },
      actor: { oid: session.oid, upn: session.upn, role: session.role },
      ipAddress: getClientIp(getRequest()),
    })
    return { job }
  })
