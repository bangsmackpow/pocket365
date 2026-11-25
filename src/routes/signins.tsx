import { useQuery } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  Filter,
  Globe,
  Info,
  Laptop,
  RefreshCw,
  Search,
  ShieldAlert,
  XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { z } from 'zod'
import {
  listSignInLogsFn,
  type EnrichedSignIn,
} from '~/server/functions/signins'

const signinsSearchSchema = z.object({
  user: z.string().optional(),
  status: z.enum(['all', 'failure', 'success', 'mfa', 'blocked']).optional(),
})

export const Route = createFileRoute('/signins')({
  validateSearch: (search) => signinsSearchSchema.parse(search),
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Sign-in Logs — Pocket365' }],
  }),
  component: SignInsPage,
})

type StatusFilter = 'all' | 'failure' | 'success' | 'mfa' | 'blocked'

function csvCell(value: string | number | boolean | null | undefined): string {
  const str = value === null || value === undefined ? '' : String(value)
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

function downloadSignInsCsv(rows: EnrichedSignIn[]): void {
  const headers = [
    'Timestamp',
    'UserDisplayName',
    'UserPrincipalName',
    'Application',
    'ClientAppUsed',
    'ErrorCode',
    'AADSTS',
    'Diagnosis',
    'FailureReason',
    'IPAddress',
    'City',
    'State',
    'Country',
    'OS',
    'Browser',
    'ConditionalAccessStatus',
    'RiskLevel',
  ]
  const lines = [
    headers.join(','),
    ...rows.map((r) =>
      [
        r.createdDateTime,
        r.userDisplayName,
        r.userPrincipalName,
        r.appDisplayName,
        r.clientAppUsed,
        r.status?.errorCode ?? 0,
        r.diagnosis.aadstsCode,
        r.diagnosis.title,
        r.status?.failureReason,
        r.ipAddress,
        r.location?.city,
        r.location?.state,
        r.location?.countryOrRegion,
        r.deviceDetail?.operatingSystem,
        r.deviceDetail?.browser,
        r.conditionalAccessStatus,
        r.riskLevelDuringSignIn,
      ]
        .map(csvCell)
        .join(','),
    ),
  ]

  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `pocket365-signins-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function formatLocation(loc: EnrichedSignIn['location']): string {
  if (!loc) return '—'
  const parts = [loc.city, loc.state, loc.countryOrRegion].filter(Boolean)
  return parts.length > 0 ? parts.join(', ') : '—'
}

function SignInsPage() {
  const searchParams = Route.useSearch()

  const [status, setStatus] = useState<StatusFilter>(
    searchParams.status ?? 'all',
  )
  const [userInput, setUserInput] = useState(searchParams.user ?? '')
  const [appInput, setAppInput] = useState('')
  const [ipInput, setIpInput] = useState('')
  const [errorCodeInput, setErrorCodeInput] = useState('')
  const [daysBack, setDaysBack] = useState<number>(7)
  const [nextLink, setNextLink] = useState<string | undefined>(undefined)

  const [applied, setApplied] = useState({
    user: searchParams.user ?? '',
    app: '',
    ipAddress: '',
    errorCode: undefined as number | undefined,
  })

  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    if (searchParams.user !== undefined) {
      setUserInput(searchParams.user)
      setApplied((prev) => ({ ...prev, user: searchParams.user ?? '' }))
      setNextLink(undefined)
    }
  }, [searchParams.user])

  const query = useQuery({
    queryKey: ['signins', status, daysBack, applied, nextLink],
    queryFn: () =>
      listSignInLogsFn({
        data: {
          status,
          daysBack,
          user: applied.user || undefined,
          app: applied.app || undefined,
          ipAddress: applied.ipAddress || undefined,
          errorCode: applied.errorCode,
          top: 50,
          nextLink,
        },
      }),
  })

  const signIns = query.data?.signIns ?? []
  const selected =
    signIns.find((item) => item.id === selectedId) ?? signIns[0] ?? null

  const applyFilters = (overrides?: Partial<typeof applied>) => {
    const rawCode = errorCodeInput.trim().replace(/^aadsts/i, '')
    const parsedCode = rawCode ? Number.parseInt(rawCode, 10) : undefined
    setNextLink(undefined)
    setApplied({
      user: userInput.trim(),
      app: appInput.trim(),
      ipAddress: ipInput.trim(),
      errorCode:
        parsedCode !== undefined && Number.isFinite(parsedCode)
          ? parsedCode
          : undefined,
      ...overrides,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Sign-in Logs Troubleshooting
          </h1>
          <p className="text-sm text-slate-600">
            Inspect Entra ID sign-in events, AADSTS failure diagnoses, MFA
            interrupts, device details, and Conditional Access evaluations.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={signIns.length === 0}
            onClick={() => downloadSignInsCsv(signIns)}
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

      {/* Friendly Permission / License Error Banner */}
      {query.data && !query.data.ok && query.data.error && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-5 text-sm text-amber-950 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-amber-900">
            <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
            <span>{query.data.error.title}</span>
          </div>
          <p className="text-xs leading-relaxed text-amber-900">
            {query.data.error.message}
          </p>
          {query.data.error.requiredPermissions &&
            query.data.error.requiredPermissions.length > 0 && (
              <div className="pt-1 text-xs space-y-1">
                <div className="font-semibold">
                  Required Microsoft Graph Application permissions (with Admin
                  Consent):
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {query.data.error.requiredPermissions.map((perm) => (
                    <code
                      key={perm}
                      className="px-2 py-0.5 rounded bg-amber-100 border border-amber-300 font-mono text-[11px]"
                    >
                      {perm}
                    </code>
                  ))}
                </div>
                <p className="text-[11px] text-amber-800 pt-1">
                  In Entra admin center → App registrations → your Graph app →
                  API permissions → Add Microsoft Graph Application permissions
                  → click <strong>Grant admin consent</strong>. Wait ~1-2
                  minutes (or restart container to refresh the cached token).
                </p>
              </div>
            )}
          {query.data.error.licenseHint && (
            <p className="text-xs text-amber-800 pt-1">
              <strong>License note:</strong> {query.data.error.licenseHint}
            </p>
          )}
        </div>
      )}

      {/* Summary KPI Strip */}
      {query.data?.ok && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            label="Events Loaded"
            value={String(query.data.summary.total)}
            sub={`Last ${daysBack} day(s)`}
          />
          <KpiCard
            label="Failures / Interrupts"
            value={String(query.data.summary.failures)}
            sub={`${query.data.summary.mfaEvents} MFA-related`}
            highlight={query.data.summary.failures > 0 ? 'rose' : 'emerald'}
          />
          <KpiCard
            label="Unique Users / IPs"
            value={`${query.data.summary.uniqueUsers} / ${query.data.summary.uniqueIps}`}
            sub="Distinct accounts & source IPs"
          />
          <KpiCard
            label="Top Error Code"
            value={query.data.summary.topError?.aadstsCode ?? 'None'}
            sub={
              query.data.summary.topError
                ? `${query.data.summary.topError.count}x — ${query.data.summary.topError.title}`
                : 'All loaded events succeeded'
            }
          />
        </div>
      )}

      {/* Preset Chips & Filters */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {(
              [
                ['all', 'All Events'],
                ['failure', 'Failures Only'],
                ['mfa', 'MFA Challenges / Failures'],
                ['blocked', 'Blocked / Lockout'],
                ['success', 'Success Only'],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                onClick={() => {
                  setStatus(value)
                  setNextLink(undefined)
                }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  status === value
                    ? 'bg-indigo-600 text-white shadow-xs'
                    : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500">Window:</span>
            <select
              value={daysBack}
              onChange={(e) => {
                setDaysBack(Number(e.target.value))
                setNextLink(undefined)
              }}
              className="px-2.5 py-1.5 border border-slate-300 rounded-lg bg-white text-xs"
            >
              <option value={1}>Last 24 hours</option>
              <option value={3}>Last 3 days</option>
              <option value={7}>Last 7 days (Entra Free max)</option>
              <option value={14}>Last 14 days (P1/P2)</option>
              <option value={30}>Last 30 days (P1/P2)</option>
            </select>
          </div>
        </div>

        <form
          className="grid grid-cols-1 md:grid-cols-5 gap-2 pt-2 border-t border-slate-100"
          onSubmit={(e) => {
            e.preventDefault()
            applyFilters()
          }}
        >
          <div className="relative md:col-span-2">
            <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              placeholder="User UPN or display name prefix..."
              className="w-full pl-8 pr-3 py-2 text-xs border border-slate-300 rounded-lg"
            />
          </div>
          <input
            type="text"
            value={appInput}
            onChange={(e) => setAppInput(e.target.value)}
            placeholder="App name (e.g. Office)"
            className="px-3 py-2 text-xs border border-slate-300 rounded-lg"
          />
          <input
            type="text"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="Exact IP address"
            className="px-3 py-2 text-xs border border-slate-300 rounded-lg"
          />
          <div className="flex gap-1.5">
            <input
              type="text"
              value={errorCodeInput}
              onChange={(e) => setErrorCodeInput(e.target.value)}
              placeholder="Error (50126)"
              className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1 px-3 py-2 rounded-lg text-xs font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer shrink-0"
            >
              <Filter className="h-3.5 w-3.5" />
              Apply
            </button>
          </div>
        </form>

        {(applied.user ||
          applied.app ||
          applied.ipAddress ||
          applied.errorCode !== undefined) && (
          <div className="flex flex-wrap items-center gap-2 text-xs pt-1">
            <span className="text-slate-500">Active filters:</span>
            {applied.user && (
              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                User: {applied.user}
              </span>
            )}
            {applied.app && (
              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                App: {applied.app}
              </span>
            )}
            {applied.ipAddress && (
              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                IP: {applied.ipAddress}
              </span>
            )}
            {applied.errorCode !== undefined && (
              <span className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                Code: AADSTS{applied.errorCode}
              </span>
            )}
            <button
              type="button"
              onClick={() => {
                setUserInput('')
                setAppInput('')
                setIpInput('')
                setErrorCodeInput('')
                setNextLink(undefined)
                setApplied({
                  user: '',
                  app: '',
                  ipAddress: '',
                  errorCode: undefined,
                })
              }}
              className="text-slate-500 underline hover:text-slate-800 cursor-pointer"
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* Main Split Table + Troubleshooting Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          {query.isLoading ? (
            <div className="p-8 text-center text-sm text-slate-500">
              Querying Microsoft Entra sign-in logs...
            </div>
          ) : signIns.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No sign-in events match your current filters.
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Time</th>
                      <th className="px-4 py-3">User & App</th>
                      <th className="px-4 py-3">Status / Diagnosis</th>
                      <th className="px-4 py-3">IP & Location</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {signIns.map((item) => {
                      const isSelected = selected?.id === item.id
                      const isOk = (item.status?.errorCode ?? 0) === 0
                      return (
                        <tr
                          key={item.id}
                          onClick={() => setSelectedId(item.id)}
                          className={`cursor-pointer transition-colors ${
                            isSelected ? 'bg-indigo-50/70' : 'hover:bg-slate-50'
                          }`}
                        >
                          <td className="px-4 py-3 whitespace-nowrap text-slate-600">
                            <div>
                              {new Date(item.createdDateTime).toLocaleDateString()}
                            </div>
                            <div className="text-[11px] text-slate-400">
                              {new Date(item.createdDateTime).toLocaleTimeString()}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-900 truncate max-w-52">
                              {item.userPrincipalName ||
                                item.userDisplayName ||
                                'Unknown'}
                            </div>
                            <div className="text-[11px] text-slate-500 truncate max-w-52">
                              {item.appDisplayName || 'Unknown App'}
                              {item.clientAppUsed
                                ? ` • ${item.clientAppUsed}`
                                : ''}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {isOk ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                                <CheckCircle2 className="h-3 w-3" />
                                Success
                              </span>
                            ) : (
                              <div className="space-y-0.5">
                                <span
                                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                                    item.diagnosis.category === 'mfa'
                                      ? 'bg-amber-50 text-amber-800 border-amber-200'
                                      : 'bg-rose-50 text-rose-700 border-rose-200'
                                  }`}
                                >
                                  <XCircle className="h-3 w-3" />
                                  {item.diagnosis.aadstsCode}
                                </span>
                                <div className="text-[11px] text-slate-600 line-clamp-1 max-w-52">
                                  {item.diagnosis.title}
                                </div>
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3 text-slate-600">
                            <div className="font-mono text-[11px]">
                              {item.ipAddress || '—'}
                            </div>
                            <div className="text-[11px] text-slate-400 truncate max-w-36">
                              {formatLocation(item.location)}
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              {query.data?.nextLink && (
                <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
                  <button
                    type="button"
                    onClick={() =>
                      setNextLink(query.data?.nextLink ?? undefined)
                    }
                    className="px-3 py-1.5 rounded-lg text-xs font-medium bg-white border border-slate-300 hover:bg-slate-100 cursor-pointer"
                  >
                    Next Page &rarr;
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* Sign-in Troubleshooting Inspector */}
        <aside className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-5">
          {!selected ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Select a sign-in event to inspect troubleshooting details.
            </div>
          ) : (
            <>
              {/* Diagnosis & Remediation Card */}
              <div
                className={`rounded-xl border p-4 space-y-2 ${
                  (selected.status?.errorCode ?? 0) === 0
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                    : selected.diagnosis.category === 'mfa'
                      ? 'bg-amber-50 border-amber-200 text-amber-950'
                      : 'bg-rose-50 border-rose-200 text-rose-950'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs font-bold">
                    {selected.diagnosis.aadstsCode}
                  </span>
                  <span className="text-[11px] uppercase tracking-wider font-semibold opacity-75">
                    {selected.diagnosis.category.replace('_', ' ')}
                  </span>
                </div>
                <div className="text-sm font-semibold">
                  {selected.diagnosis.title}
                </div>
                <p className="text-xs leading-relaxed opacity-90">
                  {selected.diagnosis.remediation}
                </p>
                {selected.status?.failureReason &&
                  selected.status.failureReason !== 'Other.' && (
                    <div className="pt-2 border-t border-black/10 text-[11px]">
                      <strong>Entra reason:</strong>{' '}
                      {selected.status.failureReason}
                    </div>
                  )}
                {selected.status?.additionalDetails && (
                  <div className="text-[11px] opacity-90">
                    <strong>Details:</strong> {selected.status.additionalDetails}
                  </div>
                )}
              </div>

              {/* Quick Pivot Actions */}
              <div className="flex flex-wrap gap-2">
                {selected.userPrincipalName && (
                  <button
                    type="button"
                    onClick={() => {
                      const upn = selected.userPrincipalName!
                      setUserInput(upn)
                      applyFilters({ user: upn })
                    }}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-800 cursor-pointer"
                  >
                    Filter by this user
                  </button>
                )}
                {selected.ipAddress && (
                  <button
                    type="button"
                    onClick={() => {
                      const ip = selected.ipAddress!
                      setIpInput(ip)
                      applyFilters({ ipAddress: ip })
                    }}
                    className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 text-slate-800 cursor-pointer"
                  >
                    Filter by IP
                  </button>
                )}
              </div>

              {/* Identity & App */}
              <div className="space-y-2 border-t border-slate-100 pt-4">
                <div className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 text-indigo-600" />
                  Identity & Application
                </div>
                <dl className="space-y-1.5 text-xs">
                  <DetailRow
                    label="User"
                    value={selected.userDisplayName || '—'}
                  />
                  <DetailRow
                    label="UPN"
                    value={selected.userPrincipalName || '—'}
                    mono
                  />
                  <DetailRow
                    label="Application"
                    value={selected.appDisplayName || '—'}
                  />
                  <DetailRow
                    label="Resource"
                    value={selected.resourceDisplayName || '—'}
                  />
                  <DetailRow
                    label="Client App"
                    value={selected.clientAppUsed || '—'}
                  />
                  <DetailRow
                    label="Timestamp"
                    value={new Date(selected.createdDateTime).toLocaleString()}
                  />
                  <DetailRow
                    label="Correlation ID"
                    value={selected.correlationId || '—'}
                    mono
                  />
                </dl>
              </div>

              {/* Network & Device */}
              <div className="space-y-2 border-t border-slate-100 pt-4">
                <div className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-indigo-600" />
                  Network & Device
                </div>
                <dl className="space-y-1.5 text-xs">
                  <DetailRow
                    label="IP Address"
                    value={selected.ipAddress || '—'}
                    mono
                  />
                  <DetailRow
                    label="Location"
                    value={formatLocation(selected.location)}
                  />
                  <DetailRow
                    label="OS / Browser"
                    value={
                      [
                        selected.deviceDetail?.operatingSystem,
                        selected.deviceDetail?.browser,
                      ]
                        .filter(Boolean)
                        .join(' / ') || '—'
                    }
                  />
                  <DetailRow
                    label="Device"
                    value={selected.deviceDetail?.displayName || 'Unmanaged / Unknown'}
                  />
                  <DetailRow
                    label="Compliant / Managed"
                    value={`${selected.deviceDetail?.isCompliant ? 'Yes' : 'No'} / ${
                      selected.deviceDetail?.isManaged ? 'Yes' : 'No'
                    }`}
                  />
                  <DetailRow
                    label="CA / Risk"
                    value={`${selected.conditionalAccessStatus || 'notApplied'} / ${
                      selected.riskLevelDuringSignIn || 'none'
                    }`}
                  />
                </dl>
              </div>

              {/* Applied Conditional Access Policies */}
              {selected.appliedConditionalAccessPolicies &&
                selected.appliedConditionalAccessPolicies.length > 0 && (
                  <div className="space-y-2 border-t border-slate-100 pt-4">
                    <div className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                      <ShieldAlert className="h-3.5 w-3.5 text-indigo-600" />
                      Conditional Access Policies (
                      {selected.appliedConditionalAccessPolicies.length})
                    </div>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {selected.appliedConditionalAccessPolicies.map((pol) => (
                        <div
                          key={pol.id}
                          className="p-2 rounded-lg border border-slate-200 text-xs flex items-center justify-between gap-2"
                        >
                          <span className="font-medium text-slate-800 truncate">
                            {pol.displayName}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold shrink-0 ${
                              pol.result === 'failure'
                                ? 'bg-rose-50 text-rose-700'
                                : pol.result === 'success'
                                  ? 'bg-emerald-50 text-emerald-700'
                                  : 'bg-slate-100 text-slate-600'
                            }`}
                          >
                            {pol.result}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              <div className="border-t border-slate-100 pt-3 flex items-center gap-1.5 text-[11px] text-slate-400">
                <Laptop className="h-3.5 w-3.5" />
                <span>Sign-in ID: {selected.id}</span>
              </div>
            </>
          )}
        </aside>
      </div>
    </div>
  )
}

function KpiCard({
  label,
  value,
  sub,
  highlight,
}: {
  label: string
  value: string
  sub: string
  highlight?: 'rose' | 'emerald'
}) {
  const valueClass =
    highlight === 'rose'
      ? 'text-rose-700'
      : highlight === 'emerald'
        ? 'text-emerald-700'
        : 'text-slate-900'

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
      <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
        {label}
      </div>
      <div className={`mt-1 text-xl font-bold truncate ${valueClass}`}>
        {value}
      </div>
      <div className="text-xs text-slate-500 mt-0.5 truncate" title={sub}>
        {sub}
      </div>
    </div>
  )
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500 shrink-0">{label}</dt>
      <dd
        className={`text-slate-900 text-right break-all ${mono ? 'font-mono text-[11px]' : ''}`}
      >
        {value}
      </dd>
    </div>
  )
}
