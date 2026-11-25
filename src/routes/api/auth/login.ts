import { createFileRoute } from '@tanstack/react-router'
import { createOidcLoginTransaction } from '~/server/auth/oidc'
import { buildOidcCookieHeader } from '~/server/auth/session'
import { buildCanonicalUrl } from '~/server/http/proxy'

export const Route = createFileRoute('/api/auth/login')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        try {
          const url = new URL(request.url)
          const returnTo = url.searchParams.get('returnTo')
          const tx = createOidcLoginTransaction(returnTo, request)

          const headers = new Headers({
            Location: tx.authorizationUrl,
            'Cache-Control': 'no-store',
          })
          headers.append(
            'Set-Cookie',
            buildOidcCookieHeader(tx.cookieBindingToken, request),
          )

          return new Response(null, { status: 302, headers })
        } catch (err) {
          const reason = encodeURIComponent(
            err instanceof Error ? err.message : 'OIDC login initialization failed.',
          )
          return new Response(null, {
            status: 302,
            headers: {
              Location: buildCanonicalUrl(
                `/login?error=config_error&detail=${reason}`,
                request,
              ),
              'Cache-Control': 'no-store',
            },
          })
        }
      },
    },
  },
})
