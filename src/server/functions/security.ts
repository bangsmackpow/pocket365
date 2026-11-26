import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireCapability, requireRole, requireSession } from '~/server/auth/guards'
import { recordAuditLog } from '~/server/db/audit'
import {
  getGraphClient,
  type GraphUserRegistrationDetail,
} from '~/server/graph/client'
import { enqueueJob, generateStrongPassword } from '~/server/graph/jobs'
import {
  isWeakMfaOnly,
  normalizeAuthMethod,
  summarizeMfaCoverage,
  type NormalizedAuthMethod,
} from '~/server/graph/mfa-helpers'
import {
  classifyGraphError,
  type FriendlyGraphError,
} from '~/server/graph/signin-errors'
import { getClientIp } from '~/server/http/proxy'
import { enforceRateLimit } from '~/server/security/rate-limit'

const userIdInputSchema = z.object({
  userId: z.string().min(1),
})

export const getUserAuthMethodsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => userIdInputSchema.parse(input))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()
    try {
      const raw = await graph.listUserAuthenticationMethods(data.userId)
      return {
        ok: true as const,
        methods: raw.map(normalizeAuthMethod),
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        methods: [] as NormalizedAuthMethod[],
        error: classifyGraphError(err, ['UserAuthenticationMethod.ReadWrite.All']),
      }
    }
  })

const revokeSessionsSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
})

export const revokeUserSessionsFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => revokeSessionsSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireCapability('helpdesk.actions', undefined, 'user.revoke_sessions')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.revokeUserSignInSessions(data.userId)
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.revoke_sessions',
        target: data.userPrincipalName,
        status: 'success',
        details: { userId: data.userId },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.revoke_sessions',
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

const resetPasswordSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  customPassword: z.string().min(12).max(128).optional(),
  forceChangePasswordNextSignIn: z.boolean().default(true),
})

export const resetUserPasswordFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => resetPasswordSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireCapability('helpdesk.actions', undefined, 'user.reset_password')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    const generated = !data.customPassword
    const newPassword = data.customPassword || generateStrongPassword(20)

    try {
      await graph.resetUserPassword(
        data.userId,
        newPassword,
        data.forceChangePasswordNextSignIn,
      )
      // Never log the plaintext password in SQLite audit_logs
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.reset_password',
        target: data.userPrincipalName,
        status: 'success',
        details: {
          userId: data.userId,
          generated,
          forceChangePasswordNextSignIn: data.forceChangePasswordNextSignIn,
        },
        ipAddress,
      })
      return {
        ok: true,
        temporaryPassword: newPassword,
        forceChangePasswordNextSignIn: data.forceChangePasswordNextSignIn,
      }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.reset_password',
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

const deleteAuthMethodSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  methodId: z.string().min(1),
  odataType: z.string().min(1),
  methodLabel: z.string().min(1),
})

export const deleteUserAuthMethodFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => deleteAuthMethodSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireCapability('helpdesk.actions', undefined, 'user.delete_auth_method')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      await graph.deleteUserAuthenticationMethod(
        data.userId,
        data.odataType,
        data.methodId,
      )
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.delete_auth_method',
        target: data.userPrincipalName,
        status: 'success',
        details: {
          userId: data.userId,
          methodId: data.methodId,
          methodLabel: data.methodLabel,
        },
        ipAddress,
      })
      return { ok: true }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.delete_auth_method',
        target: data.userPrincipalName,
        status: 'failure',
        details: {
          userId: data.userId,
          methodId: data.methodId,
          methodLabel: data.methodLabel,
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })

const createTapSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  lifetimeInMinutes: z.number().int().min(10).max(480).default(60),
  isUsableOnce: z.boolean().default(true),
})

export const createTemporaryAccessPassFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => createTapSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireCapability('helpdesk.actions', undefined, 'user.create_tap')
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    try {
      const created = await graph.createTemporaryAccessPass(data.userId, {
        lifetimeInMinutes: data.lifetimeInMinutes,
        isUsableOnce: data.isUsableOnce,
      })
      // Never persist the TAP secret value in audit_logs
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.create_tap',
        target: data.userPrincipalName,
        status: 'success',
        details: {
          userId: data.userId,
          lifetimeInMinutes: data.lifetimeInMinutes,
          isUsableOnce: data.isUsableOnce,
        },
        ipAddress,
      })
      return {
        ok: true,
        temporaryAccessPass: created.temporaryAccessPass ?? null,
        lifetimeInMinutes: created.lifetimeInMinutes ?? data.lifetimeInMinutes,
        isUsableOnce: created.isUsableOnce ?? data.isUsableOnce,
      }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.create_tap',
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

const offboardUserSchema = z.object({
  userId: z.string().min(1),
  userPrincipalName: z.string().min(1),
  mode: z.enum(['emergency_lockout', 'full_offboard']),
  disableAccount: z.boolean(),
  revokeSessions: z.boolean(),
  scramblePassword: z.boolean(),
  removeAllLicenses: z.boolean(),
  removeFromGroups: z.boolean(),
  clearManager: z.boolean(),
})

export const enqueueUserOffboardingFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => offboardUserSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.offboard')
    enforceRateLimit('heavy', session.oid)
    if (
      !data.disableAccount &&
      !data.revokeSessions &&
      !data.scramblePassword &&
      !data.removeAllLicenses &&
      !data.removeFromGroups &&
      !data.clearManager
    ) {
      throw new Error('Select at least one offboarding or lockout action.')
    }

    const job = enqueueJob({
      type: 'user.offboard',
      payload: data,
      actor: { oid: session.oid, upn: session.upn, role: session.role },
      ipAddress: getClientIp(getRequest()),
    })

    return { job }
  })

const mfaReportInputSchema = z.object({
  nextLink: z.string().url().optional(),
})

export const getMfaCoverageReportFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => mfaReportInputSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    requireSession()
    const graph = getGraphClient()

    try {
      const page = await graph.listUserRegistrationDetails({
        top: 200,
        nextLink: data.nextLink,
      })
      const summary = summarizeMfaCoverage(page.items)
      return {
        ok: true as const,
        users: page.items.map((u) => ({
          ...u,
          weakMfaOnly: isWeakMfaOnly(u),
        })),
        nextLink: page.nextLink,
        summary,
        error: null as FriendlyGraphError | null,
      }
    } catch (err) {
      return {
        ok: false as const,
        users: [] as Array<GraphUserRegistrationDetail & { weakMfaOnly: boolean }>,
        nextLink: null as string | null,
        summary: summarizeMfaCoverage([]),
        error: classifyGraphError(err, [
          'UserAuthenticationMethod.ReadWrite.All',
          'AuditLog.Read.All',
        ]),
      }
    }
  })
