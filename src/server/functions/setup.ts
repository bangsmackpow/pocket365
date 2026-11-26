import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { getCurrentSession, requireRole } from '~/server/auth/guards'
import { getConfig } from '~/server/config'
import { recordAuditLog } from '~/server/db/audit'
import { clearAllTenantGraphClients } from '~/server/graph/client'
import { getCanonicalBaseUrl, getClientIp } from '~/server/http/proxy'
import { enforceRateLimitAsync } from '~/server/security/rate-limit'
import {
  generatePowerShellBootstrapScript,
  getEffectiveEntraConfig,
  isInitialSetupRequired,
  saveEntraSetupConfig,
  testEntraGraphSetup,
  verifySetupBootstrapToken,
} from '~/server/setup/service'

export const getSetupWizardStateFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    const cfg = getConfig()
    const [session, needsSetup, effective] = await Promise.all([
      getCurrentSession(),
      isInitialSetupRequired(),
      getEffectiveEntraConfig(),
    ])

    const baseUrl = getCanonicalBaseUrl(getRequest())
    const locked = !needsSetup && session?.role !== 'owner'
    const requiresBootstrapToken = Boolean(cfg.setupBootstrapToken) && needsSetup

    return {
      deploymentMode: cfg.deploymentMode,
      needsSetup,
      locked,
      configSource: effective.source,
      requiresBootstrapToken,
      hasDedicatedEncryptionKey: cfg.dataEncryptionKey.length >= 32,
      hasSessionSecret: cfg.sessionSecret.length >= 32,
      appBaseUrl: baseUrl,
      callbackUrl: `${baseUrl}/api/auth/callback`,
      existingTenantId: locked || requiresBootstrapToken ? '' : effective.entraTenantId,
      existingOidcClientId: locked || requiresBootstrapToken ? '' : effective.oidcClientId,
      existingGraphClientId: locked || requiresBootstrapToken ? '' : effective.graphClientId,
      existingOwners: locked || requiresBootstrapToken ? '' : effective.ownerEntries.join(', '),
      powershellScript:
        locked || requiresBootstrapToken
          ? ''
          : generatePowerShellBootstrapScript(baseUrl),
    }
  },
)

const unlockSetupSchema = z.object({
  bootstrapToken: z.string().min(1, 'Setup bootstrap token is required'),
})

export const unlockSetupWizardFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => unlockSetupSchema.parse(input))
  .handler(async ({ data }) => {
    const req = getRequest()
    await enforceRateLimitAsync('auth', getClientIp(req) || 'setup', req)

    const needsSetup = await isInitialSetupRequired()
    if (!needsSetup) {
      throw new Error('Pocket365 is already configured and setup is locked.')
    }
    if (!verifySetupBootstrapToken(data.bootstrapToken)) {
      throw new Error(
        'Invalid SETUP_BOOTSTRAP_TOKEN. Check your Cloudflare Worker secret and try again.',
      )
    }

    const baseUrl = getCanonicalBaseUrl(req)
    return {
      unlocked: true,
      callbackUrl: `${baseUrl}/api/auth/callback`,
      powershellScript: generatePowerShellBootstrapScript(baseUrl),
    }
  })

const testConnectionSchema = z.object({
  bootstrapToken: z.string().optional(),
  entraTenantId: z.string().uuid('Entra Tenant ID must be a valid GUID'),
  graphClientId: z.string().uuid('Client ID must be a valid GUID'),
  graphClientSecret: z.string().optional(),
  graphCertThumbprint: z.string().optional(),
  graphCertPrivateKey: z.string().optional(),
})

export const testSetupConnectionFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => testConnectionSchema.parse(input))
  .handler(async ({ data }) => {
    const req = getRequest()
    await enforceRateLimitAsync('auth', getClientIp(req) || 'setup', req)

    const needsSetup = await isInitialSetupRequired()
    if (!needsSetup) {
      await requireRole('owner', req, 'setup.test_connection')
    } else if (!verifySetupBootstrapToken(data.bootstrapToken)) {
      throw new Error('Invalid setup bootstrap token.')
    }

    return testEntraGraphSetup({
      entraTenantId: data.entraTenantId,
      graphClientId: data.graphClientId,
      graphClientSecret: data.graphClientSecret,
      graphCertThumbprint: data.graphCertThumbprint,
      graphCertPrivateKey: data.graphCertPrivateKey,
    })
  })

const saveSetupSchema = z.object({
  bootstrapToken: z.string().optional(),
  entraTenantId: z.string().uuid('Entra Tenant ID must be a valid GUID'),
  oidcClientId: z.string().uuid('OIDC Client ID must be a valid GUID'),
  oidcClientSecret: z.string().min(8, 'OIDC Client Secret is required'),
  graphClientId: z.string().uuid().optional(),
  graphClientSecret: z.string().optional(),
  graphCertThumbprint: z.string().optional(),
  graphCertPrivateKey: z.string().optional(),
  ownerEntries: z
    .string()
    .min(3, 'Provide at least one Owner UPN or Entra Object ID'),
  adminEntries: z.string().optional(),
})

export const saveSetupConfigFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => saveSetupSchema.parse(input))
  .handler(async ({ data }) => {
    const cfg = getConfig()
    if (cfg.deploymentMode === 'saas') {
      throw new Error('Browser setup wizard is only available in self_hosted mode.')
    }

    const req = getRequest()
    await enforceRateLimitAsync('auth', getClientIp(req) || 'setup', req)

    const needsSetup = await isInitialSetupRequired()
    let actorUpn = 'setup:wizard'
    let actorOid = 'setup'
    let actorRole = 'owner'

    if (!needsSetup) {
      const session = await requireRole('owner', req, 'setup.save_config')
      actorUpn = session.upn
      actorOid = session.oid
      actorRole = session.role
    } else if (!verifySetupBootstrapToken(data.bootstrapToken)) {
      throw new Error(
        'Invalid SETUP_BOOTSTRAP_TOKEN. Check your Cloudflare Worker secret and try again.',
      )
    }

    const owners = data.ownerEntries
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
    const admins = (data.adminEntries || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)

    if (owners.length === 0) {
      throw new Error('At least one Owner UPN or Entra Object ID is required.')
    }

    const hasGraphCert = Boolean(
      data.graphCertThumbprint?.trim() && data.graphCertPrivateKey?.trim(),
    )
    const effectiveGraphSecret =
      data.graphClientSecret?.trim() ||
      (!hasGraphCert ? data.oidcClientSecret.trim() : '')

    await saveEntraSetupConfig({
      entraTenantId: data.entraTenantId,
      oidcClientId: data.oidcClientId,
      oidcClientSecret: data.oidcClientSecret,
      graphClientId: data.graphClientId || data.oidcClientId,
      graphClientSecret: effectiveGraphSecret || undefined,
      graphCertThumbprint: data.graphCertThumbprint || undefined,
      graphCertPrivateKey: data.graphCertPrivateKey || undefined,
      ownerEntries: owners,
      adminEntries: admins,
      updatedBy: actorUpn,
    })

    clearAllTenantGraphClients()

    await recordAuditLog({
      actorOid,
      actorUpn,
      actorRole,
      action: 'setup.save_entra_config',
      target: data.entraTenantId,
      status: 'success',
      details: {
        authMode: hasGraphCert ? 'certificate' : 'client_secret',
        ownerCount: owners.length,
        adminCount: admins.length,
      },
      ipAddress: getClientIp(req),
    })

    return { ok: true }
  })
