import { createFileRoute } from '@tanstack/react-router'
import { getConfigReadiness } from '~/server/config'
import { checkDatabaseHealth } from '~/server/db'
import { ensureJobWorkerStarted } from '~/server/graph/jobs'

export const Route = createFileRoute('/api/health')({
  server: {
    handlers: {
      GET: async () => {
        const dbHealth = checkDatabaseHealth()
        if (dbHealth.ok) {
          ensureJobWorkerStarted()
        }
        const config = getConfigReadiness()
        const healthy = dbHealth.ok

        return Response.json(
          {
            status: healthy ? 'ok' : 'degraded',
            app: 'pocket365',
            timestamp: new Date().toISOString(),
            checks: {
              database: dbHealth.ok ? 'ready' : 'unavailable',
              singleTenantConfigured: config.singleTenantConfigured,
              oidcConfigured: config.oidcConfigured,
              graphConfigured: config.graphConfigured,
              graphAuthMode: config.graphAuthMode,
              rbacConfigured: config.rbacConfigured,
              sessionSecretConfigured: config.sessionSecretConfigured,
              httpsBaseUrl: config.appBaseUrlHttps,
            },
          },
          {
            status: healthy ? 200 : 503,
            headers: {
              'Cache-Control': 'no-store',
            },
          },
        )
      },
    },
  },
})
