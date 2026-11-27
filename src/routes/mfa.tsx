import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  KeyRound,
  LogOut,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import {
  createTemporaryAccessPassFn,
  getMfaCoverageReportFn,
  revokeUserSessionsFn,
} from '~/server/functions/security'

export const Route = createFileRoute('/mfa')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'MFA Coverage Report — Pocket365' }],
  }),
  component: MfaReportPage,
})

type MfaFilter =
  | 'all'
  | 'missing_mfa'
  | 'admins_missing_mfa'
  | 'weak_mfa'
  | 'passwordless'
  | 'mfa_registered'

function csvCell(val: unknown): string {
  const s = val === null || val === undefined ? '' : String(val)
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function MfaReportPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'

  const [filter, setFilter] = useState<MfaFilter>('all')
  const [search, setSearch] = useState('')
  const [nextLink, setNextLink] = useState<string | undefined>(undefined)
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)
  const [generatedTap, setGeneratedTap] = useState<{
    upn: string
    code: string
    minutes: number
  } | null>(null)

  const reportQuery = useQuery({
    queryKey: ['mfa-coverage', nextLink],
    queryFn: () => getMfaCoverageReportFn({ data: { nextLink } }),
  })

  const tapMutation = useMutation({
    mutationFn: (vars: { userId: string; userPrincipalName: string }) =>
      createTemporaryAccessPassFn({
        data: {
          userId: vars.userId,
          userPrincipalName: vars.userPrincipalName,
          lifetimeInMinutes: 60,
          isUsableOnce: true,
        },
      }),
    onSuccess: (res, vars) => {
      if (res.temporaryAccessPass) {
        setGeneratedTap({
          upn: vars.userPrincipalName,
          code: res.temporaryAccessPass,
          minutes: res.lifetimeInMinutes,
        })
      }
      setBanner({
        type: 'success',
        text: `Issued Temporary Access Pass for ${vars.userPrincipalName}.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Failed to issue Temporary Access Pass (verify TAP policy is enabled in Entra ID).',
      })
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (vars: { userId: string; userPrincipalName: string }) =>
      revokeUserSessionsFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Revoked all active sessions for ${vars.userPrincipalName}.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error ? err.message : 'Failed to revoke sessions.',
      })
    },
  })

  const filteredUsers = useMemo(() => {
    const all = reportQuery.data?.users ?? []
    const q = search.trim().toLowerCase()
    return all.filter((u) => {
      if (filter === 'missing_mfa' && u.isMfaRegistered) return false
      if (filter === 'admins_missing_mfa' && (!u.isAdmin || u.isMfaRegistered))
        return false
      if (filter === 'weak_mfa' && !u.weakMfaOnly) return false
      if (filter === 'passwordless' && !u.isPasswordlessCapable) return false
      if (filter === 'mfa_registered' && !u.isMfaRegistered) return false

      if (q) {
        const matchUpn = u.userPrincipalName.toLowerCase().includes(q)
        const matchName = u.userDisplayName.toLowerCase().includes(q)
        if (!matchUpn && !matchName) return false
      }
      return true
    })
  }, [reportQuery.data?.users, filter, search])

  const exportCsv = () => {
    const headers = [
      'DisplayName',
      'UserPrincipalName',
      'IsAdmin',
      'IsMfaRegistered',
      'IsMfaCapable',
      'IsPasswordlessCapable',
      'WeakMfaOnly',
      'MethodsRegistered',
      'PreferredMethod',
    ]
    const lines = [
      headers.join(','),
      ...filteredUsers.map((u) =>
        [
          u.userDisplayName,
          u.userPrincipalName,
          u.isAdmin,
          u.isMfaRegistered,
          u.isMfaCapable,
          u.isPasswordlessCapable,
          u.weakMfaOnly,
          u.methodsRegistered.join('; '),
          u.userPreferredMethodForSecondaryAuthentication ?? '',
        ]
          .map(csvCell)
          .join(','),
      ),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `pocket365-mfa-coverage-${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  const summary = reportQuery.data?.summary

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            MFA & Passwordless Coverage
          </h1>
          <p className="text-sm text-slate-600">
            Identify accounts missing MFA, privileged admins without strong
            authentication, and users relying solely on SMS/Voice.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={filteredUsers.length === 0}
            onClick={exportCsv}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 disabled:opacity-40 cursor-pointer"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
          <button
            type="button"
            onClick={() => reportQuery.refetch()}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
          >
            <RefreshCw
              className={`h-4 w-4 ${reportQuery.isFetching ? 'animate-spin' : ''}`}
            />
            Refresh
          </button>
        </div>
      </div>

      {reportQuery.data?.isFallback && (
        <div className="rounded-xl bg-blue-50 border border-blue-200 p-4 text-xs text-blue-900 flex items-center gap-2.5">
          <CheckCircle2 className="h-4 w-4 text-blue-600 shrink-0" />
          <div>
            <span className="font-semibold">Standard Entra ID Tenant Mode: </span>
            MFA coverage and registered methods evaluated directly via Microsoft Graph per-user Authentication Methods API (no Entra ID P1/P2 license required).
          </div>
        </div>
      )}

      {reportQuery.data && !reportQuery.data.ok && reportQuery.data.error && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-5 text-sm text-amber-950 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-amber-900">
            <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
            <span>{reportQuery.data.error.title}</span>
          </div>
          <p className="text-xs">{reportQuery.data.error.message}</p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {(reportQuery.data.error.requiredPermissions ?? []).map((p) => (
              <code
                key={p}
                className="px-2 py-0.5 rounded bg-amber-100 border border-amber-300 font-mono text-[11px]"
              >
                {p}
              </code>
            ))}
          </div>
        </div>
      )}

      {generatedTap && (
        <div className="rounded-xl bg-indigo-50 border border-indigo-200 p-4 text-sm text-indigo-950 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-semibold">
              One-Time Temporary Access Pass for {generatedTap.upn} (valid{' '}
              {generatedTap.minutes} min)
            </div>
            <div className="mt-1 font-mono text-base font-bold tracking-wider bg-white px-3 py-1.5 rounded-lg border border-indigo-200 inline-block select-all">
              {generatedTap.code}
            </div>
            <p className="text-xs text-indigo-800 mt-1">
              Copy now — Pocket365 never stores TAP values in SQLite or audit
              logs.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setGeneratedTap(null)}
            className="text-xs underline cursor-pointer"
          >
            Dismiss
          </button>
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
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {reportQuery.data?.ok && summary && (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <StatCard
            label="Total Users"
            value={String(summary.total)}
            sub={`${summary.adminsTotal} privileged admin(s)`}
          />
          <StatCard
            label="MFA Registered"
            value={`${summary.mfaCoveragePct}%`}
            sub={`${summary.mfaRegistered} of ${summary.total} users`}
            tone={summary.mfaCoveragePct >= 95 ? 'emerald' : 'amber'}
          />
          <StatCard
            label="Admins Without MFA"
            value={String(summary.adminsMissingMfa)}
            sub="Critical security exposure"
            tone={summary.adminsMissingMfa > 0 ? 'rose' : 'emerald'}
          />
          <StatCard
            label="Weak MFA Only"
            value={String(summary.weakMfaOnly)}
            sub="SMS / Voice / Email only"
            tone={summary.weakMfaOnly > 0 ? 'amber' : 'emerald'}
          />
          <StatCard
            label="Passwordless Capable"
            value={`${summary.passwordlessPct}%`}
            sub={`${summary.passwordlessCapable} user(s)`}
          />
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3 shadow-xs">
        <div className="flex flex-wrap gap-1.5">
          {(
            [
              ['all', 'All Users'],
              ['missing_mfa', 'Missing MFA'],
              ['admins_missing_mfa', 'Admins Missing MFA'],
              ['weak_mfa', 'Weak MFA (SMS/Voice)'],
              ['passwordless', 'Passwordless'],
              ['mfa_registered', 'MFA Registered'],
            ] as const
          ).map(([val, label]) => (
            <button
              key={val}
              type="button"
              onClick={() => setFilter(val)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                filter === val
                  ? 'bg-indigo-600 text-white'
                  : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="relative">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter users by display name or UPN..."
            className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg"
          />
        </div>
      </div>

      {/* Results Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        {reportQuery.isLoading ? (
          <div className="p-8 text-center text-sm text-slate-500">
            Loading MFA registration report from Microsoft Graph...
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No users match this filter.
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                  <tr>
                    <th className="px-4 py-3">User</th>
                    <th className="px-4 py-3">MFA Status</th>
                    <th className="px-4 py-3">Passwordless</th>
                    <th className="px-4 py-3">Registered Methods</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredUsers.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-50/70">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-slate-900">
                            {u.userDisplayName}
                          </span>
                          {u.isAdmin && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 text-[10px] font-semibold">
                              <ShieldAlert className="h-3 w-3" />
                              Admin
                            </span>
                          )}
                        </div>
                        <div className="text-slate-500">
                          {u.userPrincipalName}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {!u.isMfaRegistered ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                            <XCircle className="h-3 w-3" />
                            Not Registered
                          </span>
                        ) : u.weakMfaOnly ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-800 border border-amber-200">
                            <AlertTriangle className="h-3 w-3" />
                            Weak (SMS/Voice)
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="h-3 w-3" />
                            Strong MFA
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {u.isPasswordlessCapable ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                            <ShieldCheck className="h-3.5 w-3.5" />
                            Yes
                          </span>
                        ) : (
                          <span className="text-slate-400">No</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {u.methodsRegistered.length === 0 ? (
                          <span className="text-slate-400">None</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {u.methodsRegistered.map((m) => (
                              <span
                                key={m}
                                className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px]"
                              >
                                {m}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right whitespace-nowrap space-x-1.5">
                        <Link
                          to="/signins"
                          search={{ user: u.userPrincipalName }}
                          className="inline-flex items-center px-2 py-1 rounded border border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
                        >
                          Sign-ins
                        </Link>
                        {isAdmin && (
                          <>
                            <button
                              type="button"
                              disabled={tapMutation.isPending}
                              onClick={() =>
                                tapMutation.mutate({
                                  userId: u.id,
                                  userPrincipalName: u.userPrincipalName,
                                })
                              }
                              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 cursor-pointer"
                            >
                              <KeyRound className="h-3 w-3" />
                              TAP
                            </button>
                            <button
                              type="button"
                              disabled={revokeMutation.isPending}
                              onClick={() =>
                                revokeMutation.mutate({
                                  userId: u.id,
                                  userPrincipalName: u.userPrincipalName,
                                })
                              }
                              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100 cursor-pointer"
                            >
                              <LogOut className="h-3 w-3" />
                              Revoke
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {reportQuery.data?.nextLink && (
              <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
                <button
                  type="button"
                  onClick={() =>
                    setNextLink(reportQuery.data?.nextLink ?? undefined)
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
    </div>
  )
}

function StatCard({
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
