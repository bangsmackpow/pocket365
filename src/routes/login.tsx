import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import { AlertTriangle, CheckCircle2, Lock, ShieldCheck, Wrench } from 'lucide-react'
import { z } from 'zod'

const loginSearchSchema = z.object({
  error: z.string().optional(),
  detail: z.string().optional(),
  returnTo: z.string().optional(),
})

export const Route = createFileRoute('/login')({
  validateSearch: (search) => loginSearchSchema.parse(search),
  beforeLoad: ({ context }) => {
    if (context.auth.user) {
      throw redirect({ to: '/' })
    }
  },
  head: () => ({
    meta: [{ title: 'Sign In — Pocket365' }],
  }),
  component: LoginPage,
})

const ERROR_MESSAGES: Record<string, string> = {
  unauthorized:
    'Your Microsoft Entra ID account is not assigned to an allowed Pocket365 admin or viewer role.',
  state_mismatch:
    'The sign-in state or security cookie could not be verified. Please try signing in again.',
  oidc_error: 'Microsoft Entra ID returned an authentication error.',
  config_error:
    'Pocket365 OIDC environment variables are incomplete. Check ENTRA_TENANT_ID, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET.',
  callback_failed: 'Failed to complete Microsoft Entra ID authentication.',
}

function LoginPage() {
  const { error, detail, returnTo } = Route.useSearch()
  const { auth } = Route.useRouteContext()
  const loginHref = returnTo
    ? `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`
    : '/api/auth/login'

  const errorMessage = error
    ? (ERROR_MESSAGES[error] ?? 'Authentication failed. Please try again.')
    : null

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
        <div className="bg-slate-900 px-8 py-7 text-white">
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-xl bg-indigo-600 flex items-center justify-center shadow">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">Pocket365</h1>
              <p className="text-xs text-slate-400">
                {auth.deploymentMode === 'saas'
                  ? 'Pocket365 Cloud SaaS — Multi-Tenant MSP Console'
                  : 'Self-Hosted Single-Tenant Microsoft 365 Admin'}
              </p>
            </div>
          </div>
        </div>

        <div className="p-8 space-y-6">
          {auth.needsSetup && (
            <div className="rounded-xl bg-indigo-50 border border-indigo-200 p-4 space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-indigo-900">
                <Wrench className="h-4 w-4 text-indigo-600 shrink-0" />
                <span>First-Time Setup Required</span>
              </div>
              <p className="text-xs text-indigo-800 leading-relaxed">
                This self-hosted Pocket365 Worker hasn&apos;t been linked to
                Microsoft Entra ID yet. Run the browser setup wizard (includes a
                1-click PowerShell bootstrap script).
              </p>
              <Link
                to="/setup"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold"
              >
                Launch First-Run Setup Wizard →
              </Link>
            </div>
          )}
          {errorMessage && (
            <div className="rounded-xl bg-rose-50 border border-rose-200 p-4 text-sm text-rose-800 space-y-1">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>Sign-in blocked</span>
              </div>
              <p className="text-xs leading-relaxed">{errorMessage}</p>
              {detail && (
                <p className="text-[11px] font-mono text-rose-700 break-words pt-1">
                  {detail}
                </p>
              )}
            </div>
          )}

          <div className="space-y-2">
            <h2 className="text-base font-semibold text-slate-900">
              Sign in with Microsoft Entra ID
            </h2>
            <p className="text-sm text-slate-600">
              Authenticate with your single-tenant organizational account. Access
              is strictly limited to configured{' '}
              <span className="font-medium text-slate-800">admin</span> and{' '}
              <span className="font-medium text-slate-800">viewer</span>{' '}
              principals or security groups.
            </p>
          </div>

          <a
            href={loginHref}
            className="w-full inline-flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold shadow-sm transition-colors"
          >
            <Lock className="h-4 w-4" />
            Continue with Microsoft Entra ID
          </a>

          <div className="pt-4 border-t border-slate-100 space-y-2 text-xs text-slate-500">
            <div className="font-medium text-slate-700">
              Instance Readiness
            </div>
            <div className="grid grid-cols-2 gap-2">
              <ReadinessPill
                label="Entra OIDC"
                ready={auth.readiness.oidcConfigured}
              />
              <ReadinessPill
                label="Graph App-Only"
                ready={auth.readiness.graphConfigured}
              />
              <ReadinessPill
                label="RBAC Rules"
                ready={auth.readiness.rbacConfigured}
              />
              <ReadinessPill
                label="Session Secret"
                ready={auth.readiness.sessionSecretConfigured}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function ReadinessPill({ label, ready }: { label: string; ready: boolean }) {
  return (
    <div
      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs ${
        ready
          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
          : 'bg-amber-50 border-amber-200 text-amber-800'
      }`}
    >
      <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
      <span className="truncate">{label}</span>
    </div>
  )
}
