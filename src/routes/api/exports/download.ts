import { createFileRoute } from '@tanstack/react-router'
import { guardApiRole } from '~/server/auth/guards'
import { getExportObject } from '~/server/cf/r2'
import { isExportKeyOwnedByOrg } from '~/server/orgs/service'

export const Route = createFileRoute('/api/exports/download')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await guardApiRole('viewer', request, 'exports.download')
        if (!auth.ok) return auth.response

        const url = new URL(request.url)
        const key = (url.searchParams.get('key') || '').trim()
        if (!key || !isExportKeyOwnedByOrg(key, auth.session.organizationId)) {
          return Response.json(
            {
              error: 'FORBIDDEN',
              message:
                'Export artifact does not belong to your organization or key is invalid.',
            },
            { status: 403 },
          )
        }

        const obj = await getExportObject(key)
        if (!obj) {
          return Response.json(
            { error: 'NOT_FOUND', message: 'Export artifact not found.' },
            { status: 404 },
          )
        }

        const filename = key.split('/').pop() || 'export.txt'
        return new Response(obj.body, {
          status: 200,
          headers: {
            'Content-Type': obj.contentType,
            'Content-Disposition': `attachment; filename="${filename.replace(/[^a-zA-Z0-9._-]/g, '_')}"`,
            'Cache-Control': 'no-store',
          },
        })
      },
    },
  },
})
