import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  Download,
  Info,
  RefreshCw,
  Search,
  UserX,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { getStaleAccountsAuditFn } from '~/server/functions/apps'
import { enqueueBulkToggleUsersFn } from '~/server/functions/users'

export const Route = createFileRoute('/cleanup')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Stale Users & Guests — Pocket365' }],
  }),
  component: StaleCleanupPage,
})

type CleanupFilter =
  | 'disabled_with_license'
  | 'stale_licensed'
  | 'guests'
  | 'stale_guests'
  | 'all'

function StaleCleanupPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'

  const [staleDays, setStaleDays] = useState(30)
  const [filter, setFilter] = useState<CleanupFilter>('disabled_with_license')
  const [search, setSearch] = useState('')
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const query = useQuery({
    queryKey: ['stale-cleanup', staleDays],
    queryFn: () => getStaleAccountsAuditFn({ data: { staleDays } }),
  })

  const bulkDisableMutation = useMutation({
    mutationFn: () =>
      enqueueBulkToggleUsersFn({
        data: { userIds: selectedIds, accountEnabled: false },
      }),
    onSuccess: (res) => {
      setSelectedIds([])
      setBanner({
        type: 'success',
        text: `Queued bulk disable job ${res.job.id} for ${selectedIds.length} account(s). Track progress in Audit & Jobs.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to queue job.',
      })
    },
  })

  const filtered = useMemo(() => {
    const rows = query.data?.rows ?? []
    const q = search.trim().toLowerCase()
    return rows.filter((r) => {
      if (
        filter === 'disabled_with_license' &&
        !r.flags.includes('disabled_with_license')
      )
        return false
      if (filter === 'stale_licensed' && !r.flags.includes('stale_licensed'))
        return false
      if (filter === 'guests' && r.userType !== 'Guest') return false
      if (filter === 'stale_guests' && !r.flags.includes('stale_guest'))
        return false
      if (q) {
        if (
          !r.displayName.toLowerCase().includes(q) &&
          !r.userPrincipalName.toLowerCase().includes(q)
        ) {
          return false
        }
      }
      return true
    })
  }, [query.data?.rows, filter, search])

  const exportCsv = () => {
    const lines = [
      'DisplayName,UserPrincipalName,UserType,Enabled,LicenseCount,LastSignIn,DaysInactive,Flags',
      ...filtered.map((r) =>
        [
          r.displayName,
          r.userPrincipalName,
          r.userType,
          r.accountEnabled,
          r.licenseCount,
          r.lastSignInDateTime ?? 'None in window',
          r.daysSinceLastSignIn ?? '',
          r.flags.join('; '),
        ]
          .map((v) => `"${String(v).replace(/"/g, '""')}"`)
          .join(','),
      ),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `pocket365-stale-cleanup-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  const toggleId = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    )
  }

  const summary = query.data?.summary

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Stale Users, License Waste & Guest Cleanup
          </h1>
          <p className="text-sm text-slate-600">
            Spot disabled accounts still consuming paid M365 licenses, inactive
            users, and stale external guests (#EXT#).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={filtered.length === 0}
            onClick={exportCsv}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 disabled:opacity-40 cursor-pointer"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
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
      </div>

      {query.data?.ok && !query.data.hasSignInActivityField && (
        <div className="rounded-xl bg-sky-50 border border-sky-200 px-4 py-3 text-xs text-sky-900 flex items-start gap-2.5">
          <Info className="h-4 w-4 text-sky-600 shrink-0 mt-0.5" />
          <div>
            <strong>Entra Free Compatibility Mode:</strong> Your tenant does not
            expose the Entra P1 <code className="font-mono">signInActivity</code>{' '}
            field on users. Pocket365 automatically correlated your last 7 days
            of Sign-in Logs and still accurately flags{' '}
            <strong>Disabled Users Holding Paid Licenses</strong> and{' '}
            <strong>External Guests</strong>.
          </div>
        </div>
      )}

      {query.data && !query.data.ok && query.data.error && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-950 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">{query.data.error.title}</div>
            <p>{query.data.error.message}</p>
          </div>
        </div>
      )}

      {banner && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          <span>{banner.text}</span>
          <Link to="/audit" className="text-xs font-semibold underline">
            View Jobs
          </Link>
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Card
            label="Disabled w/ Licenses"
            value={String(summary.disabledWithLicense)}
            sub="Immediate license savings"
            tone={summary.disabledWithLicense > 0 ? 'rose' : 'emerald'}
          />
          <Card
            label="Inactive Licensed"
            value={String(summary.staleLicensed)}
            sub={`No sign-in in ${staleDays}+ days`}
            tone={summary.staleLicensed > 0 ? 'amber' : 'emerald'}
          />
          <Card
            label="External Guests"
            value={String(summary.totalGuests)}
            sub={`${summary.staleGuests} inactive guest(s)`}
          />
          <Card
            label="Total Scanned"
            value={String(summary.totalUsers)}
            sub="Directory accounts"
          />
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1.5">
            {(
              [
                ['disabled_with_license', 'Disabled w/ Paid Licenses'],
                ['stale_licensed', 'Inactive Licensed'],
                ['guests', 'All External Guests'],
                ['stale_guests', 'Inactive Guests'],
                ['all', 'All Accounts'],
              ] as const
            ).map(([val, label]) => (
              <button
                key={val}
                type="button"
                onClick={() => setFilter(val)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
                  filter === val
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500">Inactivity threshold:</span>
            <select
              value={staleDays}
              onChange={(e) => setStaleDays(Number(e.target.value))}
              className="px-2.5 py-1.5 border border-slate-300 rounded-lg bg-white text-xs"
            >
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={60}>60 days</option>
              <option value={90}>90 days</option>
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100">
          <div className="relative flex-1 min-w-52">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by display name or UPN..."
              className="w-full pl-9 pr-3 py-2 text-xs border border-slate-300 rounded-lg"
            />
          </div>
          {isAdmin && selectedIds.length > 0 && (
            <button
              type="button"
              disabled={bulkDisableMutation.isPending}
              onClick={() => bulkDisableMutation.mutate()}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-700 text-white cursor-pointer"
            >
              <UserX className="h-3.5 w-3.5" />
              Bulk Disable ({selectedIds.length})
            </button>
          )}
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        {query.isLoading ? (
          <div className="p-8 text-center text-sm text-slate-500">
            Auditing stale accounts and guest users...
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No accounts match this cleanup view — looking tidy!
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                <tr>
                  {isAdmin && <th className="px-4 py-3 w-8" />}
                  <th className="px-4 py-3">Account</th>
                  <th className="px-4 py-3">Type / State</th>
                  <th className="px-4 py-3">Licenses</th>
                  <th className="px-4 py-3">Last Observed Sign-in</th>
                  <th className="px-4 py-3">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50/70">
                    {isAdmin && (
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(r.id)}
                          onChange={() => toggleId(r.id)}
                          className="rounded border-slate-300"
                        />
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-900">
                        {r.displayName}
                      </div>
                      <div className="text-slate-500 break-all">
                        {r.userPrincipalName}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 mr-1.5">
                        {r.userType}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-semibold ${
                          r.accountEnabled
                            ? 'bg-emerald-50 text-emerald-700'
                            : 'bg-rose-50 text-rose-700'
                        }`}
                      >
                        {r.accountEnabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-800">
                      {r.licenseCount}
                    </td>
                    <td className="px-4 py-3 text-slate-600 whitespace-nowrap">
                      {r.lastSignInDateTime
                        ? `${new Date(r.lastSignInDateTime).toLocaleDateString()} (${r.daysSinceLastSignIn}d ago)`
                        : 'No sign-in in window'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {r.flags.map((flag) => (
                          <span
                            key={flag}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                              flag === 'disabled_with_license'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : 'bg-amber-50 text-amber-800 border border-amber-200'
                            }`}
                          >
                            {flag.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function Card({
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
