import { createFileRoute } from '@tanstack/react-router'
import { getCloudflareEnv } from '~/server/cf/env'
import { checkDatabaseHealth } from '~/server/db'
import { getEffectiveConfigReadiness } from '~/server/setup/service'

export const Route = createFileRoute('/api/health')({
  server: {
    handlers: {
      GET: async () => {
        const [dbHealth, config] = await Promise.all([
          checkDatabaseHealth(),
          getEffectiveConfigReadiness(),
        ])
        const cfEnv = getCloudflareEnv()
        const healthy = dbHealth.ok

        return Response.json(
          {
            status: healthy ? 'ok' : 'degraded',
            app: 'pocket365',
            runtime: 'cloudflare-workers',
            deploymentMode: config.deploymentMode,
            timestamp: new Date().toISOString(),
            checks: {
              database: dbHealth.ok ? 'ready' : 'unavailable',
              kvBound: Boolean(cfEnv.POCKET365_KV),
              r2Bound: Boolean(cfEnv.POCKET365_R2),
              queueBound: Boolean(cfEnv.POCKET365_QUEUE),
              singleTenantConfigured: config.singleTenantConfigured,
              oidcConfigured: config.oidcConfigured,
              graphConfigured: config.graphConfigured,
              graphAuthMode: config.graphAuthMode,
              rbacConfigured: config.rbacConfigured,
              sessionSecretConfigured: config.sessionSecretConfigured,
              encryptionKeyConfigured: config.encryptionKeyConfigured,
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
