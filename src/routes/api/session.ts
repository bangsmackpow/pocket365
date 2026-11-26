import { createFileRoute } from '@tanstack/react-router'
import { guardApiRole } from '~/server/auth/guards'

export const Route = createFileRoute('/api/session')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const auth = await guardApiRole('viewer', request)
        if (!auth.ok) return auth.response
        return Response.json(
          {
            user: {
              oid: auth.session.oid,
              upn: auth.session.upn,
              displayName: auth.session.displayName,
              role: auth.session.role,
              expiresAt: auth.session.expiresAt,
            },
          },
          { headers: { 'Cache-Control': 'no-store' } },
        )
      },
    },
  },
})
