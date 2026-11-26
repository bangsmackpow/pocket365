import crypto from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { desc, eq } from 'drizzle-orm'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { requireEntitlement } from '~/server/billing/entitlements'
import { getDb } from '~/server/db'
import { recordAuditLog } from '~/server/db/audit'
import { onboardingTemplates } from '~/server/db/schema'
import { getGraphClient } from '~/server/graph/client'
import { generateStrongPassword } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'

export interface ClientOnboardingTemplate {
  id: string
  name: string
  description: string
  department: string
  jobTitle: string
  officeLocation: string
  usageLocation: string
  skuIds: string[]
  groupIds: string[]
  issueTap: boolean
  forcePasswordChange: boolean
  createdBy: string
  updatedAt: number
}

function parseJsonStringArray(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === 'string')
      : []
  } catch {
    return []
  }
}

export const getOnboardingDataFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    requireSession()
    const db = getDb()
    const graph = getGraphClient()

    const rawTemplates = db
      .select()
      .from(onboardingTemplates)
      .orderBy(desc(onboardingTemplates.updatedAt))
      .all()

    const templates: ClientOnboardingTemplate[] = rawTemplates.map((t) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      department: t.department,
      jobTitle: t.jobTitle,
      officeLocation: t.officeLocation,
      usageLocation: t.usageLocation,
      skuIds: parseJsonStringArray(t.skuIdsJson),
      groupIds: parseJsonStringArray(t.groupIdsJson),
      issueTap: t.issueTap === 1,
      forcePasswordChange: t.forcePasswordChange === 1,
      createdBy: t.createdBy,
      updatedAt: t.updatedAt,
    }))

    const [domains, skus, groupsPage] = await Promise.all([
      graph.listDomains().catch(() => []),
      graph.listSubscribedSkus().catch(() => []),
      graph.listGroups({ top: 100 }).catch(() => ({ items: [], nextLink: null })),
    ])

    return {
      templates,
      verifiedDomains: domains.filter((d) => d.isVerified),
      subscribedSkus: skus,
      groups: groupsPage.items,
    }
  },
)

const templateInputSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(2).max(80),
  description: z.string().max(240).default(''),
  department: z.string().max(120).default(''),
  jobTitle: z.string().max(120).default(''),
  officeLocation: z.string().max(120).default(''),
  usageLocation: z.string().length(2).default('US'),
  skuIds: z.array(z.string().uuid()).default([]),
  groupIds: z.array(z.string().min(1)).default([]),
  issueTap: z.boolean().default(false),
  forcePasswordChange: z.boolean().default(true),
})

export const saveOnboardingTemplateFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => templateInputSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'onboarding.save_template')
    const db = getDb()
    const id = data.id ?? crypto.randomUUID()
    const now = Date.now()

    db.insert(onboardingTemplates)
      .values({
        id,
        name: data.name.trim(),
        description: data.description.trim(),
        department: data.department.trim(),
        jobTitle: data.jobTitle.trim(),
        officeLocation: data.officeLocation.trim(),
        usageLocation: data.usageLocation.toUpperCase(),
        skuIdsJson: JSON.stringify(data.skuIds),
        groupIdsJson: JSON.stringify(data.groupIds),
        issueTap: data.issueTap ? 1 : 0,
        forcePasswordChange: data.forcePasswordChange ? 1 : 0,
        createdBy: session.upn,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: onboardingTemplates.id,
        set: {
          name: data.name.trim(),
          description: data.description.trim(),
          department: data.department.trim(),
          jobTitle: data.jobTitle.trim(),
          officeLocation: data.officeLocation.trim(),
          usageLocation: data.usageLocation.toUpperCase(),
          skuIdsJson: JSON.stringify(data.skuIds),
          groupIdsJson: JSON.stringify(data.groupIds),
          issueTap: data.issueTap ? 1 : 0,
          forcePasswordChange: data.forcePasswordChange ? 1 : 0,
          updatedAt: now,
        },
      })
      .run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'onboarding.save_template',
      target: data.name.trim(),
      status: 'success',
      details: { id, skuCount: data.skuIds.length, groupCount: data.groupIds.length },
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true, id }
  })

const deleteTemplateSchema = z.object({
  id: z.string().uuid(),
})

export const deleteOnboardingTemplateFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => deleteTemplateSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'onboarding.delete_template')
    const db = getDb()
    db.delete(onboardingTemplates)
      .where(eq(onboardingTemplates.id, data.id))
      .run()

    recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'onboarding.delete_template',
      target: data.id,
      status: 'success',
      details: {},
      ipAddress: getClientIp(getRequest()),
    })

    return { ok: true }
  })

const onboardUserSchema = z.object({
  displayName: z.string().min(2).max(120),
  givenName: z.string().max(64).default(''),
  surname: z.string().max(64).default(''),
  mailNickname: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9._-]+$/, 'Username can only contain letters, numbers, dots, underscores, or hyphens'),
  domain: z.string().min(3).max(120),
  department: z.string().max(120).default(''),
  jobTitle: z.string().max(120).default(''),
  officeLocation: z.string().max(120).default(''),
  usageLocation: z.string().length(2).default('US'),
  skuIds: z.array(z.string().uuid()).default([]),
  groupIds: z.array(z.string().min(1)).default([]),
  issueTap: z.boolean().default(false),
  forcePasswordChange: z.boolean().default(true),
})

export const onboardNewUserFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => onboardUserSchema.parse(input))
  .handler(async ({ data }) => {
    const session = requireRole('admin', undefined, 'user.onboard')
    requireEntitlement('users.onboarding', session)
    const ipAddress = getClientIp(getRequest())
    const graph = getGraphClient()

    const upn = `${data.mailNickname.trim()}@${data.domain.trim()}`
    const temporaryPassword = generateStrongPassword(20)
    const steps: Array<{ step: string; ok: boolean; error?: string }> = []

    try {
      const created = await graph.createUser({
        displayName: data.displayName.trim(),
        givenName: data.givenName.trim(),
        surname: data.surname.trim(),
        mailNickname: data.mailNickname.trim(),
        userPrincipalName: upn,
        password: temporaryPassword,
        forceChangePasswordNextSignIn: data.forcePasswordChange,
        usageLocation: data.usageLocation.toUpperCase(),
        department: data.department.trim(),
        jobTitle: data.jobTitle.trim(),
        officeLocation: data.officeLocation.trim(),
        accountEnabled: true,
      })
      steps.push({ step: 'create_user', ok: true })

      if (data.skuIds.length > 0) {
        try {
          await graph.assignUserLicenses(created.id, data.skuIds, [])
          steps.push({ step: `assign_licenses (${data.skuIds.length})`, ok: true })
        } catch (err) {
          steps.push({
            step: 'assign_licenses',
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          })
        }
      }

      for (const groupId of data.groupIds) {
        try {
          await graph.addGroupMember(groupId, created.id)
          steps.push({ step: `add_group:${groupId.slice(0, 8)}`, ok: true })
        } catch (err) {
          steps.push({
            step: `add_group:${groupId.slice(0, 8)}`,
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          })
        }
      }

      let temporaryAccessPass: string | null = null
      if (data.issueTap) {
        try {
          const tap = await graph.createTemporaryAccessPass(created.id, {
            lifetimeInMinutes: 60,
            isUsableOnce: true,
          })
          temporaryAccessPass = tap.temporaryAccessPass ?? null
          steps.push({ step: 'create_tap', ok: true })
        } catch (err) {
          steps.push({
            step: 'create_tap',
            ok: false,
            error: err instanceof Error ? err.message : String(err),
          })
        }
      }

      // Never store temporaryPassword or temporaryAccessPass in SQLite audit_logs
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.onboard',
        target: upn,
        status: 'success',
        details: {
          userId: created.id,
          skuCount: data.skuIds.length,
          groupCount: data.groupIds.length,
          issuedTap: Boolean(temporaryAccessPass),
          steps,
        },
        ipAddress,
      })

      return {
        ok: true,
        userId: created.id,
        userPrincipalName: upn,
        temporaryPassword,
        temporaryAccessPass,
        steps,
      }
    } catch (err) {
      recordAuditLog({
        actorOid: session.oid,
        actorUpn: session.upn,
        actorRole: session.role,
        action: 'user.onboard',
        target: upn,
        status: 'failure',
        details: {
          error: err instanceof Error ? err.message : String(err),
        },
        ipAddress,
      })
      throw err
    }
  })
