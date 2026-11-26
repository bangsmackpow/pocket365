import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  Lock,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import {
  getSecurityCenterDataFn,
  revokeMyOtherSessionsFn,
  revokeSessionFn,
} from '~/server/functions/sessions'

export const Route = createFileRoute('/security')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Security & Sessions — Pocket365' }],
  }),
  component: SecurityCenterPage,
})

function SecurityCenterPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()
  const [banner, setBanner] = useState<string | null>(null)

  const query = useQuery({
    queryKey: ['security-center'],
    queryFn: () => getSecurityCenterDataFn(),
  })

  const revokeOthersMutation = useMutation({
    mutationFn: () => revokeMyOtherSessionsFn(),
    onSuccess: (res) => {
      setBanner(`Revoked ${res.revokedCount} other active session(s).`)
      queryClient.invalidateQueries({ queryKey: ['security-center'] })
    },
  })

  const revokeOneMutation = useMutation({
    mutationFn: (sessionId: string) => revokeSessionFn({ data: { sessionId } }),
    onSuccess: () => {
      setBanner('Session revoked immediately.')
      queryClient.invalidateQueries({ queryKey: ['security-center'] })
    },
  })

  const controls = query.data?.controls

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            App Security & Active Sessions
          </h1>
          <p className="text-sm text-slate-600">
            Inspect active defense-in-depth protections (rate limiting, CSRF,
            CSP, SSRF, AES-256-GCM encryption), RBAC matrix, and live SQLite
            sessions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={revokeOthersMutation.isPending}
            onClick={() => revokeOthersMutation.mutate()}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign Out Other Sessions
          </button>
          <button
            type="button"
            onClick={() => query.refetch()}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${query.isFetching ? 'animate-spin' : ''}`}
            />
            Refresh
          </button>
        </div>
      </div>

      {banner && (
        <div className="rounded-xl bg-emerald-50 border border-emerald-200 px-4 py-3 text-sm text-emerald-900 flex items-center justify-between">
          <span>{banner}</span>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {controls && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          {[
            [
              'API & Auth Rate Limiting',
              '20/10m auth, 180/m API, 60/m mutations, 8/5m heavy sweeps',
              controls.rateLimiting,
            ],
            [
              'CSRF & Fetch Metadata',
              'Origin + Sec-Fetch-Site enforced on all state-changing routes',
              controls.csrfOriginCheck,
            ],
            [
              'HTTP Security Headers',
              'CSP, X-Frame-Options: DENY, nosniff, Referrer-Policy, HSTS',
              controls.securityHeaders,
            ],
            [
              'AES-256-GCM Secret Encryption',
              controls.explicitEncryptionKey
                ? 'Dedicated DATA_ENCRYPTION_KEY active'
                : 'Active (HKDF derived from SESSION_SECRET)',
              controls.webhookEncryption,
            ],
            [
              'Outbound Webhook SSRF Guard',
              controls.ssrfProtection
                ? 'Private/RFC1918/metadata IPs blocked'
                : 'ALLOW_PRIVATE_WEBHOOKS=true override',
              controls.ssrfProtection,
            ],
            [
              'Session Timeouts',
              `Idle: ${controls.sessionIdleTimeoutMinutes}m • Absolute: ${controls.sessionAbsoluteTtlHours}h • Proxy hops: ${controls.trustedProxyHops}`,
              true,
            ],
          ].map(([title, desc, active]) => (
            <div
              key={String(title)}
              className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-1"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-slate-900">{title}</span>
                <span
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                    active
                      ? 'bg-emerald-50 text-emerald-700'
                      : 'bg-amber-50 text-amber-800'
                  }`}
                >
                  <CheckCircle2 className="h-3 w-3" />
                  {active ? 'Active' : 'Custom'}
                </span>
              </div>
              <p className="text-slate-600">{desc}</p>
            </div>
          ))}
        </div>
      )}

      {/* Granular RBAC Matrix */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center gap-2 text-sm font-semibold text-slate-900">
          <Lock className="h-4 w-4 text-indigo-600" />
          Granular RBAC Capability Matrix
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
              <tr>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Env Mapping</th>
                <th className="px-4 py-3">Permitted Capabilities</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              <tr>
                <td className="px-4 py-2.5 font-semibold">owner / admin</td>
                <td className="px-4 py-2.5 font-mono text-[11px]">
                  OWNER_OIDS_OR_GROUPS / ADMIN_OIDS_OR_GROUPS
                </td>
                <td className="px-4 py-2.5 text-slate-600">
                  Full read/write: CIS 1-click fixes, Offboarding, Onboarding,
                  Roles, BitLocker reveal, Webhooks, Session revocation, Tenants
                  & Billing.
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2.5 font-semibold">helpdesk</td>
                <td className="px-4 py-2.5 font-mono text-[11px]">
                  HELPDESK_OIDS_OR_GROUPS
                </td>
                <td className="px-4 py-2.5 text-slate-600">
                  Read all + Password reset, Issue TAP, Delete MFA method,
                  Revoke user sessions, Update Out-of-Office.
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2.5 font-semibold">security_auditor</td>
                <td className="px-4 py-2.5 font-mono text-[11px]">
                  AUDITOR_OIDS_OR_GROUPS
                </td>
                <td className="px-4 py-2.5 text-slate-600">
                  Read all + Run Tenant-Wide Mailbox BEC Sweep & CIS/Audit
                  reports (no directory mutations).
                </td>
              </tr>
              <tr>
                <td className="px-4 py-2.5 font-semibold">viewer</td>
                <td className="px-4 py-2.5 font-mono text-[11px]">
                  VIEWER_OIDS_OR_GROUPS
                </td>
                <td className="px-4 py-2.5 text-slate-600">
                  Strictly read-only across all dashboards and logs.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Active Sessions */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-indigo-600" />
            Active Server-Side Sessions ({query.data?.sessions.length ?? 0})
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
              <tr>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3">Last Active</th>
                <th className="px-4 py-3">Expires</th>
                {isAdmin && <th className="px-4 py-3 text-right">Revoke</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {(query.data?.sessions ?? []).map((s) => (
                <tr key={s.id} className="hover:bg-slate-50/70">
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-900">
                      {s.displayName}{' '}
                      {s.isCurrent && (
                        <span className="ml-1 px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 text-[10px] font-semibold">
                          This browser
                        </span>
                      )}
                    </div>
                    <div className="text-slate-500">{s.userUpn}</div>
                  </td>
                  <td className="px-4 py-3 font-mono">{s.role}</td>
                  <td className="px-4 py-3 font-mono text-slate-600">
                    {s.ipAddress || '—'}
                  </td>
                  <td className="px-4 py-3 text-slate-600">
                    {new Date(s.lastSeenAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-slate-600">
                    {new Date(s.expiresAt).toLocaleString()}
                  </td>
                  {isAdmin && (
                    <td className="px-4 py-3 text-right">
                      {!s.isCurrent && (
                        <button
                          type="button"
                          disabled={revokeOneMutation.isPending}
                          onClick={() => revokeOneMutation.mutate(s.id)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-rose-600 hover:bg-rose-50 cursor-pointer"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Revoke
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
