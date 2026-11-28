import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import {
  Activity,
  AlertCircle,
  Building2,
  CheckCircle2,
  Clock,
  ExternalLink,
  Eye,
  EyeOff,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wrench,
  Zap,
} from 'lucide-react'
import { useState } from 'react'
import { Pocket365Landing } from '~/components/Pocket365Landing'
import {
  getDashboardDataFn,
  ignoreActionItemFn,
  unignoreActionItemFn,
} from '~/server/functions/dashboard'
import { applyCisRemediationFn } from '~/server/functions/governance'
import type { CisRemediationId, CisSeverity } from '~/server/graph/cis-benchmarks'

export const Route = createFileRoute('/')({
  head: () => ({
    meta: [{ title: 'Pocket365 — Microsoft 365 Security & MSP Operations' }],
  }),
  component: HomeRoute,
})

function HomeRoute() {
  const { auth } = Route.useRouteContext()
  if (!auth.user) {
    return (
      <Pocket365Landing
        deploymentMode={auth.deploymentMode}
        needsSetup={auth.needsSetup}
      />
    )
  }
  return <DashboardPage />
}

type FrameworkMode = 'all' | 'cis' | 'nist'
type ActionFilterTab = 'actionable' | 'ignored'

export function DashboardPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()

  const [framework, setFramework] = useState<FrameworkMode>('all')
  const [tab, setTab] = useState<ActionFilterTab>('actionable')
  const [severityFilter, setSeverityFilter] = useState<CisSeverity | 'all'>('all')
  const [activeRemediation, setActiveRemediation] = useState<CisRemediationId | null>(null)
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => getDashboardDataFn(),
  })

  const remediateMutation = useMutation({
    mutationFn: (remediationId: CisRemediationId) => {
      setActiveRemediation(remediationId)
      return applyCisRemediationFn({ data: { remediationId } })
    },
    onSuccess: (res) => {
      setActiveRemediation(null)
      setBanner({ type: 'success', text: res.summary })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      queryClient.invalidateQueries({ queryKey: ['cis-benchmarks'] })
    },
    onError: (err) => {
      setActiveRemediation(null)
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : '1-Click remediation failed.',
      })
    },
  })

  const ignoreMutation = useMutation({
    mutationFn: (actionItemId: string) => ignoreActionItemFn({ data: { actionItemId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  const unignoreMutation = useMutation({
    mutationFn: (actionItemId: string) => unignoreActionItemFn({ data: { actionItemId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-72 bg-slate-200 animate-pulse rounded-xl" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 bg-white border border-slate-200 rounded-2xl animate-pulse" />
          ))}
        </div>
        <div className="h-64 bg-white border border-slate-200 rounded-2xl animate-pulse" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="rounded-2xl bg-rose-50 border border-rose-200 p-6 text-sm text-rose-800 flex items-center justify-between">
        <div>
          <div className="font-semibold text-base">Failed to load dashboard</div>
          <p className="text-xs mt-1 text-rose-700">{error instanceof Error ? error.message : 'Unknown error'}</p>
        </div>
        <button
          type="button"
          onClick={() => refetch()}
          className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold"
        >
          Retry
        </button>
      </div>
    )
  }

  const defaultDomain =
    data.organization?.verifiedDomains.find((d) => d.isDefault)?.name ??
    data.organization?.verifiedDomains[0]?.name ??
    'Tenant Connected'

  const score =
    framework === 'nist'
      ? data.compliance.nistScorePct
      : data.compliance.cisScorePct
  const grade =
    score >= 85
      ? { label: 'Grade A', tone: 'emerald' }
      : score >= 70
        ? { label: 'Grade B', tone: 'indigo' }
        : score >= 55
          ? { label: 'Grade C', tone: 'amber' }
          : { label: 'Grade D', tone: 'rose' }

  const items = data.actionItems.filter((item) => {
    if (tab === 'actionable' && item.isIgnored) return false
    if (tab === 'ignored' && !item.isIgnored) return false
    if (severityFilter !== 'all' && item.severity !== severityFilter) return false
    return true
  })

  const actionableCount = data.actionItems.filter((i) => !i.isIgnored).length
  const ignoredCount = data.actionItems.filter((i) => i.isIgnored).length

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">
              Security & Operations Command Center
            </h1>
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
              <Building2 className="h-3 w-3" /> {data.organization?.displayName || defaultDomain}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Real-time compliance posture (CIS M365 & NIST SP 800-171), prioritized action queue, and tenant health telemetry.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Framework Toggle */}
          <div className="inline-flex items-center rounded-xl bg-slate-100 p-1 text-xs font-medium text-slate-600">
            <button
              type="button"
              onClick={() => setFramework('all')}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                framework === 'all' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'hover:text-slate-900'
              }`}
            >
              Unified View
            </button>
            <button
              type="button"
              onClick={() => setFramework('cis')}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                framework === 'cis' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'hover:text-slate-900'
              }`}
            >
              CIS M365
            </button>
            <button
              type="button"
              onClick={() => setFramework('nist')}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                framework === 'nist' ? 'bg-white text-slate-900 shadow-xs font-semibold' : 'hover:text-slate-900'
              }`}
            >
              NIST SP 800-171
            </button>
          </div>

          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer shadow-2xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            Re-scan
          </button>

          <Link
            to="/admin"
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold bg-slate-900 text-white hover:bg-slate-800 cursor-pointer shadow-2xs"
          >
            <Wrench className="h-3.5 w-3.5" />
            System & API Admin
          </Link>
        </div>
      </div>

      {banner && (
        <div
          className={`rounded-2xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          <span>{banner.text}</span>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs font-semibold opacity-70 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}

      {data.graphError && (
        <div className="rounded-2xl bg-amber-50 border border-amber-200 p-4 text-sm text-amber-900 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="font-semibold">Microsoft Graph Status Warning</div>
            <p className="text-xs mt-0.5">{data.graphError}</p>
          </div>
        </div>
      )}

      {/* KPI Scorecards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Compliance Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              {framework === 'nist'
                ? 'NIST SP 800-171'
                : framework === 'cis'
                  ? 'CIS M365 Benchmark'
                  : 'Unified Compliance Posture'}
            </span>
            <ShieldCheck className="h-5 w-5 text-indigo-600" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">{score}%</span>
            <span
              className={`text-xs font-bold px-2 py-0.5 rounded-full ${
                grade.tone === 'emerald'
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : grade.tone === 'indigo'
                    ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                    : grade.tone === 'amber'
                      ? 'bg-amber-50 text-amber-700 border border-amber-200'
                      : 'bg-rose-50 text-rose-700 border border-rose-200'
              }`}
            >
              {grade.label}
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-500">
            {data.compliance.passed} passed • {data.compliance.failed} failed • {data.compliance.oneClickFixable} 1-click fixes
          </div>
        </div>

        {/* MFA Coverage Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              MFA Enforcement
            </span>
            <ShieldAlert className="h-5 w-5 text-emerald-600" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">{data.mfa.allUsersMfaPct}%</span>
            <span className="text-xs text-slate-500 font-medium">All Users</span>
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
            <span>Admin MFA: <strong className="text-slate-800">{data.mfa.adminMfaPct}%</strong></span>
            <Link to="/mfa" className="text-indigo-600 hover:underline font-medium">Inspect →</Link>
          </div>
        </div>

        {/* License Efficiency Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              License Efficiency
            </span>
            <Layers className="h-5 w-5 text-indigo-600" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">{data.license.utilizationPct}%</span>
            <span className="text-xs text-slate-500 font-medium">Assigned</span>
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
            <span>Unassigned Seats: <strong className="text-slate-800">{data.license.unassignedCount}</strong></span>
            <Link to="/cleanup" className="text-indigo-600 hover:underline font-medium">Reclaim →</Link>
          </div>
        </div>

        {/* Background Jobs Card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Background Automation
            </span>
            <Clock className="h-5 w-5 text-sky-600" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">
              {data.recentJobs.filter((j) => j.status === 'queued' || j.status === 'running').length}
            </span>
            <span className="text-xs text-slate-500 font-medium">Active Jobs</span>
          </div>
          <div className="mt-2 text-xs text-slate-500 flex items-center justify-between">
            <span>Audit Sweep: <strong className="text-slate-800">Every 15m</strong></span>
            <Link to="/audit" className="text-indigo-600 hover:underline font-medium">Queue →</Link>
          </div>
        </div>
      </div>

      {/* Priority Action Items / To-Dos */}
      <section className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-amber-100 text-amber-800 flex items-center justify-center">
              <Zap className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Action Items & Security To-Dos
              </h2>
              <p className="text-xs text-slate-500">
                Prioritized items requiring admin action. Resolve in 1 click or dismiss known exceptions.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Actionable vs Ignored Tabs */}
            <div className="inline-flex items-center rounded-xl bg-slate-100 p-1 text-xs font-semibold text-slate-600">
              <button
                type="button"
                onClick={() => setTab('actionable')}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  tab === 'actionable' ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
                }`}
              >
                Needs Attention ({actionableCount})
              </button>
              <button
                type="button"
                onClick={() => setTab('ignored')}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  tab === 'ignored' ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
                }`}
              >
                Ignored Exceptions ({ignoredCount})
              </button>
            </div>

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as CisSeverity | 'all')}
              className="px-3 py-1.5 rounded-xl border border-slate-300 text-xs font-medium bg-white"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
            </select>
          </div>
        </div>

        {items.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <div className="h-12 w-12 rounded-2xl bg-emerald-100 text-emerald-700 flex items-center justify-center mx-auto">
              <CheckCircle2 className="h-6 w-6" />
            </div>
            <div className="text-base font-semibold text-slate-900">
              {tab === 'actionable' ? 'All Clear! No Action Items Pending' : 'No Ignored Action Items'}
            </div>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {tab === 'actionable'
                ? 'Your Microsoft 365 tenant matches recommended CIS & NIST security baselines. Scheduled cron sweeps will notify you if any controls drift.'
                : 'Exceptions you ignore will appear here with the option to restore them back to the active queue.'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {items.map((item) => {
              const cisTag = item.cisRef
              const nistTag = item.nistRef

              return (
                <div
                  key={item.id}
                  className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-50/70 transition-colors"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                          item.severity === 'critical'
                            ? 'bg-rose-100 text-rose-800'
                            : item.severity === 'high'
                              ? 'bg-amber-100 text-amber-800'
                              : 'bg-blue-100 text-blue-800'
                        }`}
                      >
                        {item.severity}
                      </span>

                      {/* Framework Tag Display based on selector */}
                      {(framework === 'all' || framework === 'cis') && cisTag && (
                        <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded-md bg-slate-100 text-slate-700">
                          {cisTag}
                        </span>
                      )}
                      {(framework === 'all' || framework === 'nist') && nistTag && (
                        <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-700 border border-indigo-200">
                          {nistTag}
                        </span>
                      )}

                      <span className="text-xs text-slate-400">• {item.category}</span>
                    </div>

                    <div className="text-sm font-semibold text-slate-900">{item.title}</div>
                    <p className="text-xs text-slate-600 line-clamp-2">{item.description}</p>
                    {item.isIgnored && item.ignoredReason && (
                      <p className="text-[11px] text-amber-700 italic">Ignored note: {item.ignoredReason}</p>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    {!item.isIgnored ? (
                      <>
                        {item.remediationId && isAdmin && (
                          <button
                            type="button"
                            disabled={remediateMutation.isPending && activeRemediation === item.remediationId}
                            onClick={() => remediateMutation.mutate(item.remediationId!)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold shadow-xs cursor-pointer"
                          >
                            <Sparkles className="h-3.5 w-3.5" />
                            {remediateMutation.isPending && activeRemediation === item.remediationId
                              ? 'Applying...'
                              : '1-Click Fix'}
                          </button>
                        )}

                        <Link
                          to="/cis"
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-medium"
                        >
                          Details <ExternalLink className="h-3 w-3" />
                        </Link>

                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => ignoreMutation.mutate(item.actionItemId)}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-slate-400 hover:text-slate-600 hover:bg-slate-100 text-xs cursor-pointer"
                            title="Ignore / Dismiss this item"
                          >
                            <EyeOff className="h-3.5 w-3.5" /> Ignore
                          </button>
                        )}
                      </>
                    ) : (
                      <button
                        type="button"
                        onClick={() => unignoreMutation.mutate(item.actionItemId)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold shadow-2xs cursor-pointer"
                      >
                        <Eye className="h-3.5 w-3.5" /> Restore to Queue
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </section>

      {/* Subscribed Licenses & Recent Activity Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Licenses */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Layers className="h-4 w-4 text-indigo-600" />
              Subscribed Licenses & Utilization
            </h2>
            <Link to="/cleanup" className="text-xs font-medium text-indigo-600 hover:underline">
              Inspect Inactive Users →
            </Link>
          </div>
          <div className="p-6">
            {data.subscribedSkus.length === 0 ? (
              <p className="text-xs text-slate-500">No subscribed SKUs found.</p>
            ) : (
              <div className="space-y-4">
                {data.subscribedSkus.map((sku) => {
                  const enabled = sku.prepaidUnits.enabled || 0
                  const consumed = sku.consumedUnits || 0
                  const pct = enabled > 0 ? Math.min(100, Math.round((consumed / enabled) * 100)) : 0
                  return (
                    <div key={sku.id} className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-slate-800">{sku.skuPartNumber}</span>
                        <span className="text-slate-500">
                          {consumed} / {enabled} assigned ({pct}%)
                        </span>
                      </div>
                      <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            pct > 90 ? 'bg-amber-500' : 'bg-indigo-600'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </section>

        {/* Recent Audit Events */}
        <section className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-600" />
              Recent Administrative Audit Log
            </h2>
            <Link to="/audit" className="text-xs font-medium text-indigo-600 hover:underline">
              Full Log →
            </Link>
          </div>
          <div className="divide-y divide-slate-100">
            {data.recentAudits.length === 0 ? (
              <div className="p-6 text-xs text-slate-500">No audit log entries recorded yet.</div>
            ) : (
              data.recentAudits.slice(0, 5).map((entry) => (
                <div key={entry.id} className="px-6 py-3 flex items-center justify-between gap-3 text-xs">
                  <div className="min-w-0">
                    <div className="font-medium text-slate-900 truncate">
                      {entry.action} <span className="text-slate-400 font-normal">({entry.target})</span>
                    </div>
                    <div className="text-slate-500 truncate text-[11px]">
                      {entry.actorUpn} • {new Date(entry.createdAt).toLocaleTimeString()}
                    </div>
                  </div>
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold ${
                      entry.status === 'success'
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : 'bg-rose-50 text-rose-700 border border-rose-200'
                    }`}
                  >
                    {entry.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  )
}
