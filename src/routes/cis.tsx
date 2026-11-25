import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  ExternalLink,
  RefreshCw,
  Wrench,
  XCircle,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import {
  applyCisRemediationFn,
  runCisBenchmarkScanFn,
} from '~/server/functions/governance'
import type {
  CisCategory,
  CisCheckResult,
  CisRemediationId,
} from '~/server/graph/cis-benchmarks'

export const Route = createFileRoute('/cis')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'CIS Benchmarks — Pocket365' }],
  }),
  component: CisBenchmarksPage,
})

type StatusFilter = 'all' | 'actionable' | 'fixable' | 'pass' | 'unavailable'

function CisBenchmarksPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [categoryFilter, setCategoryFilter] = useState<CisCategory | 'all'>('all')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)
  const [activeRemediation, setActiveRemediation] =
    useState<CisRemediationId | null>(null)

  const scanQuery = useQuery({
    queryKey: ['cis-benchmarks'],
    queryFn: () => runCisBenchmarkScanFn(),
  })

  const remediateMutation = useMutation({
    mutationFn: (remediationId: CisRemediationId) => {
      setActiveRemediation(remediationId)
      return applyCisRemediationFn({ data: { remediationId } })
    },
    onSuccess: (res) => {
      setActiveRemediation(null)
      setBanner({ type: 'success', text: res.summary })
      queryClient.invalidateQueries({ queryKey: ['cis-benchmarks'] })
    },
    onError: (err) => {
      setActiveRemediation(null)
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Remediation failed. Verify Policy.ReadWrite.* permissions are granted with Admin Consent.',
      })
    },
  })

  const filteredChecks = useMemo(() => {
    const list = scanQuery.data?.checks ?? []
    return list.filter((c) => {
      if (categoryFilter !== 'all' && c.category !== categoryFilter) return false
      if (statusFilter === 'actionable' && c.status !== 'fail' && c.status !== 'warn')
        return false
      if (
        statusFilter === 'fixable' &&
        !((c.status === 'fail' || c.status === 'warn') && c.remediationId)
      )
        return false
      if (statusFilter === 'pass' && c.status !== 'pass') return false
      if (statusFilter === 'unavailable' && c.status !== 'unavailable')
        return false
      return true
    })
  }, [scanQuery.data?.checks, statusFilter, categoryFilter])

  const summary = scanQuery.data?.summary

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            CIS Microsoft 365 Benchmarks
          </h1>
          <p className="text-sm text-slate-600">
            Live tenant hardening posture with step-by-step remediation guides
            and audited 1-click fixes for Graph-remediable controls.
          </p>
        </div>
        <button
          type="button"
          onClick={() => scanQuery.refetch()}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${scanQuery.isFetching ? 'animate-spin' : ''}`}
          />
          Re-scan Tenant
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

      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <ScoreCard
            label="CIS Score"
            value={`${summary.scorePct}%`}
            sub={`${summary.passed} of ${summary.evaluated} evaluated`}
            tone={
              summary.scorePct >= 85
                ? 'emerald'
                : summary.scorePct >= 60
                  ? 'amber'
                  : 'rose'
            }
          />
          <ScoreCard
            label="Failed"
            value={String(summary.failed)}
            sub={`${summary.warned} warning(s)`}
            tone={summary.failed > 0 ? 'rose' : 'emerald'}
          />
          <ScoreCard
            label="1-Click Fixable"
            value={String(summary.oneClickFixable)}
            sub="Safe Graph auto-fixes"
            tone={summary.oneClickFixable > 0 ? 'indigo' : 'emerald'}
          />
          <ScoreCard
            label="Passed"
            value={String(summary.passed)}
            sub="Compliant controls"
            tone="emerald"
          />
          <ScoreCard
            label="Needs Permission"
            value={String(summary.unavailable)}
            sub="Grant Graph scopes to scan"
            tone={summary.unavailable > 0 ? 'amber' : undefined}
          />
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex flex-wrap gap-1.5">
          {(
            [
              ['all', 'All Controls'],
              ['actionable', 'Failed & Warnings'],
              ['fixable', '1-Click Fixable'],
              ['pass', 'Passed'],
              ['unavailable', 'Missing Permission'],
            ] as const
          ).map(([val, label]) => (
            <button
              key={val}
              type="button"
              onClick={() => setStatusFilter(val)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                statusFilter === val
                  ? 'bg-indigo-600 text-white'
                  : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <select
          value={categoryFilter}
          onChange={(e) =>
            setCategoryFilter(e.target.value as CisCategory | 'all')
          }
          className="px-3 py-1.5 text-xs border border-slate-300 rounded-lg bg-white"
        >
          <option value="all">All categories</option>
          <option value="Identity & MFA">Identity & MFA</option>
          <option value="Privileged Access">Privileged Access</option>
          <option value="Apps & Consent">Apps & Consent</option>
          <option value="Guests & Collaboration">Guests & Collaboration</option>
        </select>
      </div>

      {/* Controls List */}
      {scanQuery.isLoading ? (
        <div className="bg-white rounded-xl border border-slate-200 p-10 text-center text-sm text-slate-500">
          Evaluating live tenant policies against CIS Microsoft 365
          Benchmarks...
        </div>
      ) : filteredChecks.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-10 text-center text-sm text-slate-500">
          No benchmark controls match this filter.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredChecks.map((check) => (
            <CisCheckCard
              key={check.id}
              check={check}
              isAdmin={isAdmin}
              isFixing={
                remediateMutation.isPending &&
                activeRemediation === check.remediationId
              }
              onFix={(id) => remediateMutation.mutate(id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function CisCheckCard({
  check,
  isAdmin,
  isFixing,
  onFix,
}: {
  check: CisCheckResult
  isAdmin: boolean
  isFixing: boolean
  onFix: (id: CisRemediationId) => void
}) {
  const statusStyles =
    check.status === 'pass'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
      : check.status === 'fail'
        ? 'bg-rose-50 text-rose-700 border-rose-200'
        : check.status === 'warn'
          ? 'bg-amber-50 text-amber-800 border-amber-200'
          : 'bg-slate-100 text-slate-600 border-slate-200'

  const severityStyles =
    check.severity === 'critical'
      ? 'bg-rose-100 text-rose-800'
      : check.severity === 'high'
        ? 'bg-amber-100 text-amber-900'
        : 'bg-sky-100 text-sky-800'

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded">
              {check.cisRef}
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase ${severityStyles}`}
            >
              {check.severity}
            </span>
            <span className="text-xs text-slate-500">{check.category}</span>
          </div>
          <h3 className="text-sm font-semibold text-slate-900">{check.title}</h3>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold border ${statusStyles}`}
          >
            {check.status === 'pass' ? (
              <CheckCircle2 className="h-3.5 w-3.5" />
            ) : check.status === 'fail' ? (
              <XCircle className="h-3.5 w-3.5" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5" />
            )}
            {check.status === 'unavailable' ? 'Needs Permission' : check.status.toUpperCase()}
          </span>

          {isAdmin && check.remediationId && (
            <button
              type="button"
              disabled={isFixing}
              onClick={() => onFix(check.remediationId!)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
            >
              <Wrench className="h-3.5 w-3.5" />
              {isFixing ? 'Applying...' : check.remediationLabel || '1-Click Fix'}
            </button>
          )}

          {check.linkTo && (
            <Link
              to={check.linkTo}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50"
            >
              Open
              <ExternalLink className="h-3 w-3" />
            </Link>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-50 rounded-lg p-3 border border-slate-100">
        <div>
          <div className="text-[11px] font-semibold uppercase text-slate-500">
            Observed Value
          </div>
          <div className="text-slate-900 mt-0.5 break-words">
            {check.currentValue}
          </div>
        </div>
        <div>
          <div className="text-[11px] font-semibold uppercase text-slate-500">
            CIS Recommendation
          </div>
          <div className="text-slate-700 mt-0.5">{check.expectedValue}</div>
        </div>
      </div>

      <details open={check.status === 'fail' || check.status === 'warn'}>
        <summary className="cursor-pointer text-xs font-semibold text-indigo-700 inline-flex items-center gap-1.5">
          <ClipboardCheck className="h-3.5 w-3.5" />
          How to Resolve & Required Permissions
        </summary>
        <div className="mt-2 pl-4 space-y-2 text-xs text-slate-700">
          <ol className="list-decimal pl-4 space-y-1">
            {check.howToResolve.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[11px] text-slate-500">
            <span>Graph permissions:</span>
            {check.requiredPermissions.map((perm) => (
              <code
                key={perm}
                className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-slate-800"
              >
                {perm}
              </code>
            ))}
          </div>
        </div>
      </details>
    </div>
  )
}

function ScoreCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string
  value: string
  sub: string
  tone?: 'emerald' | 'amber' | 'rose' | 'indigo'
}) {
  const color =
    tone === 'rose'
      ? 'text-rose-700'
      : tone === 'amber'
        ? 'text-amber-700'
        : tone === 'emerald'
          ? 'text-emerald-700'
          : tone === 'indigo'
            ? 'text-indigo-700'
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
