import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createRootRouteWithContext,
  HeadContent,
  Outlet,
  Scripts,
  useRouterState,
} from '@tanstack/react-router'
import { AppShell } from '~/components/AppShell'
import { getSessionFn } from '~/server/functions/auth'
import appCss from '~/styles/app.css?url'

export interface RouterContext {
  queryClient: QueryClient
}

export const Route = createRootRouteWithContext<RouterContext>()({
  beforeLoad: async () => {
    const auth = await getSessionFn()
    return { auth }
  },
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Pocket365 — Microsoft 365 Management' },
    ],
    links: [{ rel: 'stylesheet', href: appCss }],
  }),
  component: RootDocument,
  notFoundComponent: NotFoundPage,
})

function RootDocument() {
  const { queryClient, auth } = Route.useRouteContext()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const isLoginRoute = pathname === '/login'

  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body className="min-h-screen bg-slate-50 text-slate-900">
        <QueryClientProvider client={queryClient}>
          {auth.user && !isLoginRoute ? (
            <AppShell user={auth.user} tenantIdHint={auth.tenantIdHint}>
              <Outlet />
            </AppShell>
          ) : (
            <Outlet />
          )}
        </QueryClientProvider>
        <Scripts />
      </body>
    </html>
  )
}

function NotFoundPage() {
  return (
    <div className="min-h-[60vh] flex flex-col items-center justify-center p-8 text-center space-y-3">
      <h1 className="text-3xl font-bold text-slate-900">404</h1>
      <p className="text-sm text-slate-600">
        The requested Pocket365 page could not be found.
      </p>
      <a
        href="/"
        className="px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700"
      >
        Return to Dashboard
      </a>
    </div>
  )
}
