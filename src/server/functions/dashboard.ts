import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { requireRole, requireSession } from '~/server/auth/guards'
import { getConfigReadiness } from '~/server/config'
import { listAuditLogs, recordAuditLog } from '~/server/db/audit'
import {
  getRuntimeSettings,
  runtimeSettingsSchema,
  updateRuntimeSettings,
} from '~/server/db/settings'
import {
  getGraphClient,
  type GraphOrganization,
  type GraphSubscribedSku,
} from '~/server/graph/client'
import { listJobs } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'

export const getDashboardDataFn = createServerFn({ method: 'GET' }).handler(
  async () => {
    await requireSession()

    const readiness = getConfigReadiness()
    const [settings, recentAudits, recentJobs] = await Promise.all([
      getRuntimeSettings(),
      listAuditLogs({ limit: 8 }),
      listJobs({ limit: 8 }),
    ])

    let organization: GraphOrganization | null = null
    let subscribedSkus: GraphSubscribedSku[] = []
    let graphError: string | null = null

    if (readiness.graphConfigured) {
      try {
        const graph = await getGraphClient()
        const [org, skus] = await Promise.all([
          graph.getOrganization(),
          graph.listSubscribedSkus(),
        ])
        organization = org
        subscribedSkus = skus
      } catch (err) {
        graphError =
          err instanceof Error
            ? err.message
            : 'Unable to query Microsoft Graph API.'
      }
    } else {
      graphError =
        'Microsoft Graph app-only credentials are not yet configured.'
    }

    return {
      readiness,
      settings,
      organization,
      subscribedSkus,
      graphError,
      recentAudits,
      recentJobs,
    }
  },
)

export const updateRuntimeSettingsFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => runtimeSettingsSchema.partial().parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'settings.update')
    const updated = await updateRuntimeSettings(data, session.upn)

    await recordAuditLog({
      actorOid: session.oid,
      actorUpn: session.upn,
      actorRole: session.role,
      action: 'settings.update',
      target: 'runtime_settings',
      status: 'success',
      details: updated,
      ipAddress: getClientIp(getRequest()),
    })

    return updated
  })
