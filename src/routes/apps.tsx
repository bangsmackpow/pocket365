import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  AppWindow,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import {
  listAppsAndGrantsFn,
  revokeOAuthGrantFn,
} from '~/server/functions/apps'

export const Route = createFileRoute('/apps')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Apps & OAuth Grants — Pocket365' }],
  }),
  component: AppsAndOAuthPage,
})

function AppsAndOAuthPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [tab, setTab] = useState<'credentials' | 'grants'>('credentials')
  const [onlyRiskyGrants, setOnlyRiskyGrants] = useState(false)
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const query = useQuery({
    queryKey: ['apps-and-grants'],
    queryFn: () => listAppsAndGrantsFn(),
  })

  const revokeMutation = useMutation({
    mutationFn: (vars: {
      grantId: string
      clientDisplayName: string
      scopes: string[]
    }) => revokeOAuthGrantFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Revoked OAuth permission grant for ${vars.clientDisplayName}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['apps-and-grants'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to revoke grant.',
      })
    },
  })

  const data = query.data
  const visibleGrants = (data?.grants ?? []).filter(
    (g) => !onlyRiskyGrants || g.isHighRisk,
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            App Registrations & OAuth Grants
          </h1>
          <p className="text-sm text-slate-600">
            Track expiring client secrets and certificates before outages occur,
            and audit or revoke risky delegated OAuth app consents.
          </p>
        </div>
        <button
          type="button"
          onClick={() => query.refetch()}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${query.isFetching ? 'animate-spin' : ''}`}
          />
          Refresh
        </button>
      </div>

      {banner && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          <span>{banner.text}</span>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            label="App Registrations"
            value={String(data.appCount)}
            sub={`${data.credentials.length} secret/cert credential(s)`}
          />
          <MetricCard
            label="Expired Credentials"
            value={String(data.summary.expired)}
            sub="Already expired"
            tone={data.summary.expired > 0 ? 'rose' : 'emerald'}
          />
          <MetricCard
            label="Expiring ≤ 30 / 60d"
            value={`${data.summary.critical} / ${data.summary.warning}`}
            sub="Rotate before expiry"
            tone={
              data.summary.critical > 0
                ? 'rose'
                : data.summary.warning > 0
                  ? 'amber'
                  : 'emerald'
            }
          />
          <MetricCard
            label="High-Risk OAuth Grants"
            value={String(data.summary.highRiskGrants)}
            sub={`of ${data.grants.length} delegated grant(s)`}
            tone={data.summary.highRiskGrants > 0 ? 'amber' : 'emerald'}
          />
        </div>
      )}

      <div className="border-b border-slate-200 flex gap-6">
        <button
          type="button"
          onClick={() => setTab('credentials')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer ${
            tab === 'credentials'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <KeyRound className="h-4 w-4" />
          Expiring Secrets & Certs ({data?.credentials.length ?? 0})
        </button>
        <button
          type="button"
          onClick={() => setTab('grants')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer ${
            tab === 'grants'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <AppWindow className="h-4 w-4" />
          OAuth Permission Grants ({data?.grants.length ?? 0})
        </button>
      </div>

      {tab === 'credentials' ? (
        <div className="space-y-4">
          {data?.appsError && (
            <ErrorBox
              title={data.appsError.title}
              message={data.appsError.message}
              permissions={data.appsError.requiredPermissions}
            />
          )}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            {query.isLoading ? (
              <div className="p-8 text-center text-sm text-slate-500">
                Scanning Entra app registrations...
              </div>
            ) : (data?.credentials.length ?? 0) === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500">
                No app secrets or certificates found.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Application</th>
                      <th className="px-4 py-3">Credential</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Expires</th>
                      <th className="px-4 py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {data!.credentials.map((c) => (
                      <tr key={`${c.appObjectId}-${c.keyId}`} className="hover:bg-slate-50/70">
                        <td className="px-4 py-3">
                          <div className="font-medium text-slate-900">
                            {c.appDisplayName}
                          </div>
                          <div className="text-[11px] font-mono text-slate-400">
                            {c.appId}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {c.credentialName}
                        </td>
                        <td className="px-4 py-3 capitalize text-slate-600">
                          {c.credentialType}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-slate-600">
                          {c.endDateTime
                            ? new Date(c.endDateTime).toLocaleDateString()
                            : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                              c.state === 'expired'
                                ? 'bg-rose-50 text-rose-700 border-rose-200'
                                : c.state === 'critical'
                                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                                  : c.state === 'warning'
                                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            }`}
                          >
                            {c.daysRemaining === null
                              ? 'Unknown'
                              : c.daysRemaining < 0
                                ? `Expired ${Math.abs(c.daysRemaining)}d ago`
                                : `${c.daysRemaining}d left`}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {data?.grantsError && (
            <ErrorBox
              title={data.grantsError.title}
              message={data.grantsError.message}
              permissions={data.grantsError.requiredPermissions}
            />
          )}
          <div className="flex justify-end">
            <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={onlyRiskyGrants}
                onChange={(e) => setOnlyRiskyGrants(e.target.checked)}
                className="rounded border-slate-300"
              />
              Show high-risk scopes only (Mail / Files / Directory write)
            </label>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            {visibleGrants.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500">
                No matching OAuth permission grants found.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Client App</th>
                      <th className="px-4 py-3">Consent</th>
                      <th className="px-4 py-3">Granted Scopes</th>
                      {isAdmin && <th className="px-4 py-3 text-right">Action</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {visibleGrants.map((g) => (
                      <tr key={g.id} className="hover:bg-slate-50/70">
                        <td className="px-4 py-3">
                          <div className="font-medium text-slate-900 flex items-center gap-1.5">
                            {g.isHighRisk && (
                              <ShieldAlert className="h-3.5 w-3.5 text-rose-600 shrink-0" />
                            )}
                            <span>{g.clientDisplayName}</span>
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Resource: {g.resourceDisplayName}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                              g.consentType === 'AllPrincipals'
                                ? 'bg-purple-50 text-purple-700'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                          >
                            {g.consentType === 'AllPrincipals'
                              ? 'Tenant-Wide'
                              : 'User Consent'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1 max-w-md">
                            {g.scopes.map((sc) => {
                              const risky = g.riskyScopes.includes(sc)
                              return (
                                <span
                                  key={sc}
                                  className={`px-1.5 py-0.5 rounded font-mono text-[10px] ${
                                    risky
                                      ? 'bg-rose-50 text-rose-700 border border-rose-200 font-semibold'
                                      : 'bg-slate-100 text-slate-700'
                                  }`}
                                >
                                  {sc}
                                </span>
                              )
                            })}
                          </div>
                        </td>
                        {isAdmin && (
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              disabled={revokeMutation.isPending}
                              onClick={() =>
                                revokeMutation.mutate({
                                  grantId: g.id,
                                  clientDisplayName: g.clientDisplayName,
                                  scopes: g.scopes,
                                })
                              }
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100 cursor-pointer"
                            >
                              <Trash2 className="h-3 w-3" />
                              Revoke
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function MetricCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string
  value: string
  sub: string
  tone?: 'emerald' | 'amber' | 'rose'
}) {
  const color =
    tone === 'rose'
      ? 'text-rose-700'
      : tone === 'amber'
        ? 'text-amber-700'
        : tone === 'emerald'
          ? 'text-emerald-700'
          : 'text-slate-900'

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
      <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className={`mt-1 text-xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500 mt-0.5">{sub}</div>
    </div>
  )
}

function ErrorBox({
  title,
  message,
  permissions,
}: {
  title: string
  message: string
  permissions?: string[]
}) {
  return (
    <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-950 space-y-1.5">
      <div className="font-semibold flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0" />
        <span>{title}</span>
      </div>
      <p>{message}</p>
      {permissions && permissions.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-0.5">
          {permissions.map((p) => (
            <code
              key={p}
              className="px-1.5 py-0.5 rounded bg-amber-100 border border-amber-300 font-mono text-[11px]"
            >
              {p}
            </code>
          ))}
        </div>
      )}
    </div>
  )
}
