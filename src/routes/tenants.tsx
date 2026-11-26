import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect, useRouter } from '@tanstack/react-router'
import {
  Building2,
  CheckCircle2,
  ExternalLink,
  Plus,
  Radar,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UserCheck,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'
import { z } from 'zod'
import {
  addManagedTenantFn,
  deleteManagedTenantFn,
  generateAdminConsentLinkFn,
  getTenantsCommandCenterFn,
  grantTenantAccessFn,
  revokeTenantAccessFn,
  runCrossTenantPostureScanFn,
  switchActiveTenantFn,
  testTenantConnectionFn,
} from '~/server/functions/tenants'

const tenantsSearchSchema = z.object({
  onboarded: z.string().optional(),
  error: z.string().optional(),
})

export const Route = createFileRoute('/tenants')({
  validateSearch: (search) => tenantsSearchSchema.parse(search),
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Multi-Tenant Command Center — Pocket365' }],
  }),
  component: TenantsCommandCenterPage,
})

function TenantsCommandCenterPage() {
  const { auth } = Route.useRouteContext()
  const searchParams = Route.useSearch()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()
  const router = useRouter()

  const [entraTenantId, setEntraTenantId] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [primaryDomain, setPrimaryDomain] = useState('')
  const [connectionMode, setConnectionMode] = useState<
    'admin_consent' | 'app_credentials'
  >('admin_consent')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [consentUrl, setConsentUrl] = useState<string | null>(null)

  const [accessPrincipal, setAccessPrincipal] = useState('')
  const [accessTenantId, setAccessTenantId] = useState('')

  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(
    searchParams.error
      ? { type: 'error', text: searchParams.error }
      : searchParams.onboarded
        ? {
            type: 'success',
            text: 'Customer tenant onboarded via Microsoft Admin Consent!',
          }
        : null,
  )

  const query = useQuery({
    queryKey: ['tenants-command-center'],
    queryFn: () => getTenantsCommandCenterFn(),
  })

  const switchMutation = useMutation({
    mutationFn: (managedTenantId: string) =>
      switchActiveTenantFn({ data: { managedTenantId } }),
    onSuccess: async (res) => {
      setBanner({
        type: 'success',
        text: `Switched active workspace to "${res.activeTenant.displayName}".`,
      })
      await queryClient.invalidateQueries()
      await router.invalidate()
    },
  })

  const addMutation = useMutation({
    mutationFn: () =>
      addManagedTenantFn({
        data: {
          entraTenantId,
          displayName,
          primaryDomain: primaryDomain || undefined,
          connectionMode,
          clientId: clientId || undefined,
          clientSecret: clientSecret || undefined,
        },
      }),
    onSuccess: async () => {
      setEntraTenantId('')
      setDisplayName('')
      setPrimaryDomain('')
      setClientId('')
      setClientSecret('')
      setBanner({
        type: 'success',
        text: 'Managed tenant registered (credentials encrypted with AES-256-GCM).',
      })
      await queryClient.invalidateQueries()
      await router.invalidate()
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to add tenant.',
      })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (managedTenantId: string) =>
      deleteManagedTenantFn({ data: { managedTenantId } }),
    onSuccess: async () => {
      setBanner({ type: 'success', text: 'Managed tenant removed.' })
      await queryClient.invalidateQueries()
      await router.invalidate()
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to remove tenant.',
      })
    },
  })

  const testMutation = useMutation({
    mutationFn: (managedTenantId: string) =>
      testTenantConnectionFn({ data: { managedTenantId } }),
    onSuccess: (res) => {
      setBanner({
        type: 'success',
        text: `Connected to ${res.displayName} (${res.primaryDomain || 'verified'}).`,
      })
      queryClient.invalidateQueries({ queryKey: ['tenants-command-center'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error ? err.message : 'Tenant connection test failed.',
      })
      queryClient.invalidateQueries({ queryKey: ['tenants-command-center'] })
    },
  })

  const consentMutation = useMutation({
    mutationFn: () => generateAdminConsentLinkFn(),
    onSuccess: (res) => {
      setConsentUrl(res.consentUrl)
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Failed to generate Admin Consent URL.',
      })
    },
  })

  const postureScanMutation = useMutation({
    mutationFn: () => runCrossTenantPostureScanFn(),
    onSuccess: (res) => {
      setBanner({
        type: 'success',
        text: `Cross-tenant CIS & MFA posture scan completed across ${res.results.length} tenant(s).`,
      })
      queryClient.invalidateQueries({ queryKey: ['tenants-command-center'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Cross-tenant posture scan failed.',
      })
    },
  })

  const grantAccessMutation = useMutation({
    mutationFn: () =>
      grantTenantAccessFn({
        data: {
          principal: accessPrincipal,
          managedTenantId: accessTenantId,
        },
      }),
    onSuccess: () => {
      setAccessPrincipal('')
      setBanner({ type: 'success', text: 'Technician tenant scope added.' })
      queryClient.invalidateQueries({ queryKey: ['tenants-command-center'] })
    },
  })

  const revokeAccessMutation = useMutation({
    mutationFn: (id: string) => revokeTenantAccessFn({ data: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants-command-center'] })
    },
  })

  const tenants = query.data?.tenants ?? []
  const tenantNameById = new Map(tenants.map((t) => [t.id, t.displayName]))

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Multi-Tenant MSP Command Center
          </h1>
          <p className="text-sm text-slate-600">
            Manage multiple Microsoft 365 customer tenants with strict per-tenant
            Graph token isolation, 1-click Admin Consent onboarding, and
            cross-tenant CIS/MFA posture visibility.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <button
              type="button"
              disabled={postureScanMutation.isPending}
              onClick={() => postureScanMutation.mutate()}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
            >
              <Radar className="h-3.5 w-3.5" />
              {postureScanMutation.isPending
                ? 'Scanning All Tenants...'
                : 'Scan All Tenants (CIS + MFA)'}
            </button>
          )}
          <button
            type="button"
            onClick={() => query.refetch()}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${query.isFetching ? 'animate-spin' : ''}`}
            />
            Refresh
          </button>
        </div>
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
            className="text-xs underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Managed Tenants Table */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Building2 className="h-4 w-4 text-indigo-600" />
            Managed Tenants ({tenants.length} /{' '}
            {query.data?.plan.maxTenants ?? '—'} quota)
          </h2>
          <span className="text-xs text-slate-500">
            Switching tenants updates every Pocket365 view immediately
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
              <tr>
                <th className="px-4 py-3">Tenant</th>
                <th className="px-4 py-3">Mode</th>
                <th className="px-4 py-3">Health</th>
                <th className="px-4 py-3">CIS Score</th>
                <th className="px-4 py-3">MFA Coverage</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {tenants.map((t) => {
                const isActive = query.data?.activeTenantId === t.id
                return (
                  <tr
                    key={t.id}
                    className={isActive ? 'bg-indigo-50/60' : 'hover:bg-slate-50/70'}
                  >
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-900 flex items-center gap-2">
                        <span>{t.displayName}</span>
                        {t.isPrimary && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px]">
                            Primary
                          </span>
                        )}
                        {isActive && (
                          <span className="px-1.5 py-0.5 rounded bg-indigo-100 text-indigo-700 text-[10px] font-semibold">
                            Active
                          </span>
                        )}
                      </div>
                      <div className="text-slate-500 font-mono text-[11px]">
                        {t.primaryDomain ? `${t.primaryDomain} • ` : ''}
                        {t.entraTenantId}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-600">
                      {t.connectionMode}
                    </td>
                    <td className="px-4 py-3">
                      {t.status === 'active' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-700 font-semibold">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Active
                        </span>
                      ) : (
                        <span
                          title={t.lastHealthError || undefined}
                          className="inline-flex items-center gap-1 text-rose-700 font-semibold"
                        >
                          <XCircle className="h-3.5 w-3.5" />
                          {t.status}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-semibold">
                      {t.lastCisScorePct !== null ? `${t.lastCisScorePct}%` : '—'}
                    </td>
                    <td className="px-4 py-3 font-semibold">
                      {t.lastMfaCoveragePct !== null
                        ? `${t.lastMfaCoveragePct}%`
                        : '—'}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap space-x-1.5">
                      {!isActive && (
                        <button
                          type="button"
                          onClick={() => switchMutation.mutate(t.id)}
                          className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-medium cursor-pointer"
                        >
                          Switch
                        </button>
                      )}
                      {isAdmin && (
                        <>
                          <button
                            type="button"
                            disabled={testMutation.isPending}
                            onClick={() => testMutation.mutate(t.id)}
                            className="px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 cursor-pointer"
                          >
                            Test
                          </button>
                          {!t.isPrimary && (
                            <button
                              type="button"
                              disabled={deleteMutation.isPending}
                              onClick={() => deleteMutation.mutate(t.id)}
                              className="p-1.5 rounded text-rose-600 hover:bg-rose-50 cursor-pointer align-middle"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {isAdmin && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Onboard New Tenant */}
          <section className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4 text-xs">
            <div className="font-semibold text-sm text-slate-900 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-indigo-600" />
              Onboard Customer Tenant
            </div>

            <div className="rounded-lg bg-indigo-50 border border-indigo-200 p-3.5 space-y-2">
              <div className="font-semibold text-indigo-950">
                Option 1: 1-Click Microsoft Admin Consent (Multi-Tenant App)
              </div>
              <p className="text-indigo-900">
                Generate a single-use consent link to send to a customer Global
                Administrator (requires your Graph App Registration to be set to
                Multi-Tenant with redirect URI{' '}
                <code className="font-mono">
                  /api/tenants/consent-callback
                </code>
                ).
              </p>
              <button
                type="button"
                disabled={consentMutation.isPending}
                onClick={() => consentMutation.mutate()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold cursor-pointer"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Generate Admin Consent Link
              </button>
              {consentUrl && (
                <div className="pt-1 space-y-1">
                  <div className="font-mono text-[11px] bg-white border border-indigo-200 rounded p-2 break-all select-all">
                    {consentUrl}
                  </div>
                  <a
                    href={consentUrl}
                    className="inline-flex items-center gap-1 text-indigo-700 font-semibold underline"
                  >
                    Open consent prompt now &rarr;
                  </a>
                </div>
              )}
            </div>

            <form
              className="space-y-3 pt-2 border-t border-slate-100"
              onSubmit={(e) => {
                e.preventDefault()
                addMutation.mutate()
              }}
            >
              <div className="font-semibold text-slate-800">
                Option 2: Register Tenant Manually (Encrypted Credentials)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Customer Name (e.g. Acme Corp)"
                  className="px-3 py-2 border border-slate-300 rounded-lg"
                />
                <input
                  type="text"
                  required
                  value={entraTenantId}
                  onChange={(e) => setEntraTenantId(e.target.value)}
                  placeholder="Entra Tenant GUID"
                  className="px-3 py-2 border border-slate-300 rounded-lg font-mono"
                />
                <input
                  type="text"
                  value={primaryDomain}
                  onChange={(e) => setPrimaryDomain(e.target.value)}
                  placeholder="Primary domain (optional)"
                  className="px-3 py-2 border border-slate-300 rounded-lg"
                />
                <select
                  value={connectionMode}
                  onChange={(e) =>
                    setConnectionMode(
                      e.target.value as 'admin_consent' | 'app_credentials',
                    )
                  }
                  className="px-3 py-2 border border-slate-300 rounded-lg bg-white"
                >
                  <option value="app_credentials">
                    Dedicated App Credentials
                  </option>
                  <option value="admin_consent">
                    Shared Multi-Tenant App (Consented)
                  </option>
                </select>
              </div>

              {connectionMode === 'app_credentials' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <input
                    type="text"
                    required
                    value={clientId}
                    onChange={(e) => setClientId(e.target.value)}
                    placeholder="Tenant Graph App Client ID"
                    className="px-3 py-2 border border-slate-300 rounded-lg font-mono"
                  />
                  <input
                    type="password"
                    required
                    value={clientSecret}
                    onChange={(e) => setClientSecret(e.target.value)}
                    placeholder="Client Secret (AES-256-GCM encrypted)"
                    className="px-3 py-2 border border-slate-300 rounded-lg"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={addMutation.isPending}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold cursor-pointer"
              >
                <Plus className="h-3.5 w-3.5" />
                Add Managed Tenant
              </button>
            </form>
          </section>

          {/* Per-Tenant Technician Scoping */}
          <section className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4 text-xs">
            <div className="font-semibold text-sm text-slate-900 flex items-center gap-2">
              <UserCheck className="h-4 w-4 text-indigo-600" />
              Per-Tenant Technician Access Scoping
            </div>
            <p className="text-slate-600">
              Owners and Admins automatically access all tenants. Scope Helpdesk,
              Auditor, or Viewer users to specific customer tenants below.
            </p>
            <form
              className="flex flex-wrap gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                grantAccessMutation.mutate()
              }}
            >
              <input
                type="text"
                required
                value={accessPrincipal}
                onChange={(e) => setAccessPrincipal(e.target.value)}
                placeholder="Technician UPN or Entra OID"
                className="flex-1 min-w-44 px-3 py-2 border border-slate-300 rounded-lg"
              />
              <select
                required
                value={accessTenantId}
                onChange={(e) => setAccessTenantId(e.target.value)}
                className="px-3 py-2 border border-slate-300 rounded-lg bg-white"
              >
                <option value="">Select tenant...</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.displayName}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                disabled={grantAccessMutation.isPending}
                className="px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold cursor-pointer"
              >
                Grant
              </button>
            </form>

            {(query.data?.accessRules.length ?? 0) === 0 ? (
              <p className="text-slate-500">
                No per-tenant technician scoping rules configured yet.
              </p>
            ) : (
              <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
                {query.data!.accessRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="px-3 py-2 flex items-center justify-between gap-2"
                  >
                    <div>
                      <span className="font-mono font-medium text-slate-900">
                        {rule.principal}
                      </span>{' '}
                      &rarr;{' '}
                      <span className="font-semibold text-indigo-700">
                        {tenantNameById.get(rule.managedTenantId) ??
                          rule.managedTenantId}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => revokeAccessMutation.mutate(rule.id)}
                      className="p-1 rounded text-rose-600 hover:bg-rose-50 cursor-pointer"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  )
}
