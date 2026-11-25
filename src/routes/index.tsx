import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  Activity,
  AlertCircle,
  Building2,
  CheckCircle2,
  Clock,
  KeyRound,
  Save,
  Settings,
  ShieldCheck,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  getDashboardDataFn,
  updateRuntimeSettingsFn,
} from '~/server/functions/dashboard'

export const Route = createFileRoute('/')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Dashboard — Pocket365' }],
  }),
  component: DashboardPage,
})

function DashboardPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => getDashboardDataFn(),
  })

  const [defaultPageSize, setDefaultPageSize] = useState(25)
  const [auditRetentionDays, setAuditRetentionDays] = useState(90)
  const [organizationBanner, setOrganizationBanner] = useState('')
  const [bulkJobDelayMs, setBulkJobDelayMs] = useState(150)
  const [saveMessage, setSaveMessage] = useState<string | null>(null)

  useEffect(() => {
    if (data?.settings) {
      setDefaultPageSize(data.settings.defaultPageSize)
      setAuditRetentionDays(data.settings.auditRetentionDays)
      setOrganizationBanner(data.settings.organizationBanner)
      setBulkJobDelayMs(data.settings.bulkJobDelayMs)
    }
  }, [data?.settings])

  const saveSettingsMutation = useMutation({
    mutationFn: () =>
      updateRuntimeSettingsFn({
        data: {
          defaultPageSize,
          auditRetentionDays,
          organizationBanner,
          bulkJobDelayMs,
        },
      }),
    onSuccess: () => {
      setSaveMessage('Runtime settings saved and recorded in audit log.')
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (err) => {
      setSaveMessage(
        err instanceof Error ? err.message : 'Failed to save settings.',
      )
    },
  })

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-56 bg-slate-200 animate-pulse rounded-lg" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-28 bg-white border border-slate-200 rounded-xl animate-pulse"
            />
          ))}
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="rounded-xl bg-rose-50 border border-rose-200 p-5 text-sm text-rose-800">
        Failed to load dashboard:{' '}
        {error instanceof Error ? error.message : 'Unknown error'}
      </div>
    )
  }

  const defaultDomain =
    data.organization?.verifiedDomains.find((d) => d.isDefault)?.name ??
    data.organization?.verifiedDomains[0]?.name ??
    'Not connected'

  const activeJobsCount = data.recentJobs.filter(
    (j) => j.status === 'queued' || j.status === 'running',
  ).length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Pocket365 Overview
          </h1>
          <p className="text-sm text-slate-600">
            Single-tenant Microsoft 365 directory, licensing, and audit console.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/users"
            className="px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          >
            Manage Users
          </Link>
          <Link
            to="/groups"
            className="px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors"
          >
            Manage Groups
          </Link>
        </div>
      </div>

      {data.settings.organizationBanner && (
        <div className="rounded-xl bg-indigo-50 border border-indigo-200 px-4 py-3 text-sm text-indigo-950">
          {data.settings.organizationBanner}
        </div>
      )}

      {data.graphError && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-sm text-amber-900 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Microsoft Graph Status</div>
            <p className="text-xs mt-0.5">{data.graphError}</p>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Tenant
            </span>
            <Building2 className="h-4 w-4 text-indigo-600" />
          </div>
          <div className="mt-2 text-lg font-semibold text-slate-900 truncate">
            {data.organization?.displayName ?? 'Single-Tenant Mode'}
          </div>
          <div className="text-xs text-slate-500 mt-1 truncate">
            Primary domain: {defaultDomain}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Graph Auth Mode
            </span>
            <KeyRound className="h-4 w-4 text-emerald-600" />
          </div>
          <div className="mt-2 text-lg font-semibold text-slate-900 capitalize">
            {data.readiness.graphAuthMode.replace('_', ' ')}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {data.subscribedSkus.length} subscribed license SKU(s)
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Background Jobs
            </span>
            <Clock className="h-4 w-4 text-sky-600" />
          </div>
          <div className="mt-2 text-lg font-semibold text-slate-900">
            {activeJobsCount} active / {data.recentJobs.length} recent
          </div>
          <div className="text-xs text-slate-500 mt-1">
            SQLite-backed async worker queue
          </div>
        </div>
      </div>

      {/* License Utilization */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-indigo-600" />
            Subscribed Licenses
          </h2>
          <span className="text-xs text-slate-500">
            Live from Microsoft Graph
          </span>
        </div>
        {data.subscribedSkus.length === 0 ? (
          <div className="p-6 text-sm text-slate-500">
            No subscribed SKUs available (verify Graph{' '}
            <code className="font-mono text-xs">Organization.Read.All</code>{' '}
            permission).
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                <tr>
                  <th className="px-5 py-3">SKU Part Number</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Consumed / Enabled</th>
                  <th className="px-5 py-3 w-48">Utilization</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.subscribedSkus.map((sku) => {
                  const enabled = sku.prepaidUnits.enabled
                  const pct =
                    enabled > 0
                      ? Math.min(100, Math.round((sku.consumedUnits / enabled) * 100))
                      : 0
                  return (
                    <tr key={sku.id} className="hover:bg-slate-50/70">
                      <td className="px-5 py-3 font-medium text-slate-900">
                        <div>{sku.skuPartNumber}</div>
                        <div className="text-[11px] font-mono text-slate-400">
                          {sku.skuId}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                          {sku.capabilityStatus}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-slate-700">
                        {sku.consumedUnits} / {enabled}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                pct > 90 ? 'bg-rose-500' : 'bg-indigo-600'
                              }`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs text-slate-500 w-9 text-right">
                            {pct}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Audit Events */}
        <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-600" />
              Recent Audit Events
            </h2>
            <Link
              to="/audit"
              className="text-xs font-medium text-indigo-600 hover:text-indigo-700"
            >
              View all
            </Link>
          </div>
          <div className="divide-y divide-slate-100">
            {data.recentAudits.length === 0 ? (
              <div className="p-5 text-sm text-slate-500">
                No audit events recorded yet.
              </div>
            ) : (
              data.recentAudits.map((entry) => (
                <div
                  key={entry.id}
                  className="px-5 py-3 flex items-center justify-between gap-3 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-medium text-slate-900 truncate">
                      {entry.action}{' '}
                      <span className="text-slate-500 font-normal">
                        ({entry.target})
                      </span>
                    </div>
                    <div className="text-slate-500 truncate">
                      {entry.actorUpn} •{' '}
                      {new Date(entry.createdAt).toLocaleString()}
                    </div>
                  </div>
                  <StatusBadge status={entry.status} />
                </div>
              ))
            )}
          </div>
        </section>

        {/* Non-Secret Runtime Settings */}
        <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Settings className="h-4 w-4 text-indigo-600" />
              Runtime Settings (Non-Secret)
            </h2>
            <span className="text-xs text-slate-500">
              {isAdmin ? 'Admin editable' : 'Read-only'}
            </span>
          </div>
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <label className="block space-y-1">
                <span className="text-xs font-medium text-slate-700">
                  Default Page Size
                </span>
                <input
                  type="number"
                  min={10}
                  max={100}
                  disabled={!isAdmin}
                  value={defaultPageSize}
                  onChange={(e) => setDefaultPageSize(Number(e.target.value))}
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-xs font-medium text-slate-700">
                  Audit Retention (Days)
                </span>
                <input
                  type="number"
                  min={7}
                  max={3650}
                  disabled={!isAdmin}
                  value={auditRetentionDays}
                  onChange={(e) =>
                    setAuditRetentionDays(Number(e.target.value))
                  }
                  className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
                />
              </label>
            </div>

            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-700">
                Bulk Job Throttle Delay (ms)
              </span>
              <input
                type="number"
                min={0}
                max={5000}
                disabled={!isAdmin}
                value={bulkJobDelayMs}
                onChange={(e) => setBulkJobDelayMs(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
              />
            </label>

            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-700">
                Operator Notice Banner
              </span>
              <input
                type="text"
                maxLength={240}
                placeholder="Optional maintenance or tenant notice..."
                disabled={!isAdmin}
                value={organizationBanner}
                onChange={(e) => setOrganizationBanner(e.target.value)}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
              />
            </label>

            {saveMessage && (
              <div className="flex items-center gap-2 text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-2 rounded-lg">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{saveMessage}</span>
              </div>
            )}

            {isAdmin && (
              <button
                type="button"
                disabled={saveSettingsMutation.isPending}
                onClick={() => {
                  setSaveMessage(null)
                  saveSettingsMutation.mutate()
                }}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
              >
                <Save className="h-4 w-4" />
                {saveSettingsMutation.isPending ? 'Saving...' : 'Save Settings'}
              </button>
            )}
          </div>
        </section>
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles =
    status === 'success' || status === 'completed'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
      : status === 'failure' || status === 'failed'
        ? 'bg-rose-50 text-rose-700 border-rose-200'
        : 'bg-amber-50 text-amber-700 border-amber-200'
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${styles}`}
    >
      {status}
    </span>
  )
}
