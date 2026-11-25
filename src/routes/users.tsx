import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  KeyRound,
  RefreshCw,
  Search,
  UserCheck,
  UserX,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'
import {
  enqueueBulkAssignLicenseFn,
  enqueueBulkToggleUsersFn,
  getUserDetailFn,
  listUsersFn,
  toggleUserAccountFn,
  updateUserLicensesFn,
} from '~/server/functions/users'
import { getUserSignInsFn } from '~/server/functions/signins'

export const Route = createFileRoute('/users')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Users — Pocket365' }],
  }),
  component: UsersPage,
})

function UsersPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [searchInput, setSearchInput] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [nextLink, setNextLink] = useState<string | undefined>(undefined)
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [checkedIds, setCheckedIds] = useState<string[]>([])
  const [bulkSkuId, setBulkSkuId] = useState('')
  const [feedback, setFeedback] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const usersQuery = useQuery({
    queryKey: ['users', appliedSearch, nextLink],
    queryFn: () =>
      listUsersFn({
        data: {
          search: appliedSearch || undefined,
          nextLink,
        },
      }),
  })

  const detailQuery = useQuery({
    queryKey: ['user-detail', selectedUserId],
    enabled: Boolean(selectedUserId),
    queryFn: () => getUserDetailFn({ data: { userId: selectedUserId! } }),
  })

  const userSignInsQuery = useQuery({
    queryKey: ['user-signins', selectedUserId],
    enabled: Boolean(selectedUserId),
    queryFn: () =>
      getUserSignInsFn({ data: { userIdOrUpn: selectedUserId!, top: 6 } }),
  })

  const toggleMutation = useMutation({
    mutationFn: (params: {
      userId: string
      userPrincipalName: string
      accountEnabled: boolean
    }) => toggleUserAccountFn({ data: params }),
    onSuccess: (_res, vars) => {
      setFeedback({
        type: 'success',
        text: `Account ${vars.accountEnabled ? 'enabled' : 'disabled'} for ${vars.userPrincipalName}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({
        queryKey: ['user-detail', vars.userId],
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to update account.',
      })
    },
  })

  const licenseMutation = useMutation({
    mutationFn: (params: {
      userId: string
      userPrincipalName: string
      addSkuIds: string[]
      removeSkuIds: string[]
    }) => updateUserLicensesFn({ data: params }),
    onSuccess: (_res, vars) => {
      setFeedback({
        type: 'success',
        text: `Updated licenses for ${vars.userPrincipalName}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({
        queryKey: ['user-detail', vars.userId],
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to update licenses.',
      })
    },
  })

  const bulkToggleMutation = useMutation({
    mutationFn: (accountEnabled: boolean) =>
      enqueueBulkToggleUsersFn({
        data: { userIds: checkedIds, accountEnabled },
      }),
    onSuccess: (res) => {
      setCheckedIds([])
      setFeedback({
        type: 'success',
        text: `Queued background job ${res.job.id} (${res.job.type}). Check Audit & Jobs for progress.`,
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to enqueue job.',
      })
    },
  })

  const bulkLicenseMutation = useMutation({
    mutationFn: (mode: 'assign' | 'remove') =>
      enqueueBulkAssignLicenseFn({
        data: {
          userIds: checkedIds,
          addSkuIds: mode === 'assign' ? [bulkSkuId] : [],
          removeSkuIds: mode === 'remove' ? [bulkSkuId] : [],
        },
      }),
    onSuccess: (res) => {
      setCheckedIds([])
      setFeedback({
        type: 'success',
        text: `Queued bulk license job ${res.job.id}. Check Audit & Jobs for status.`,
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text:
          err instanceof Error ? err.message : 'Failed to enqueue license job.',
      })
    },
  })

  const skus = usersQuery.data?.subscribedSkus ?? []
  const skuNameById = new Map(skus.map((s) => [s.skuId, s.skuPartNumber]))

  const toggleChecked = (id: string) => {
    setCheckedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Users & Licenses
          </h1>
          <p className="text-sm text-slate-600">
            Search Entra ID users, inspect account state, and manage Microsoft
            365 license assignments.
          </p>
        </div>
        <button
          type="button"
          onClick={() => usersQuery.refetch()}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${usersQuery.isFetching ? 'animate-spin' : ''}`}
          />
          Refresh
        </button>
      </div>

      {feedback && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
            feedback.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          <span>{feedback.text}</span>
          <div className="flex items-center gap-3 shrink-0">
            {feedback.type === 'success' && (
              <Link
                to="/audit"
                className="text-xs font-semibold underline hover:opacity-80"
              >
                View Audit & Jobs
              </Link>
            )}
            <button
              type="button"
              onClick={() => setFeedback(null)}
              className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Search & Bulk Actions */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3 shadow-xs">
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            setNextLink(undefined)
            setAppliedSearch(searchInput.trim())
          }}
        >
          <div className="relative flex-1 min-w-60">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by display name, UPN, or email..."
              className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
          >
            Search
          </button>
          {appliedSearch && (
            <button
              type="button"
              onClick={() => {
                setSearchInput('')
                setAppliedSearch('')
                setNextLink(undefined)
              }}
              className="px-3 py-2 rounded-lg text-sm font-medium border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
            >
              Clear
            </button>
          )}
        </form>

        {isAdmin && checkedIds.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100 text-xs">
            <span className="font-semibold text-slate-700">
              {checkedIds.length} selected (Async Job):
            </span>
            <button
              type="button"
              disabled={bulkToggleMutation.isPending}
              onClick={() => bulkToggleMutation.mutate(true)}
              className="px-2.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white font-medium cursor-pointer"
            >
              Bulk Enable
            </button>
            <button
              type="button"
              disabled={bulkToggleMutation.isPending}
              onClick={() => bulkToggleMutation.mutate(false)}
              className="px-2.5 py-1.5 rounded-md bg-rose-600 hover:bg-rose-700 text-white font-medium cursor-pointer"
            >
              Bulk Disable
            </button>
            {skus.length > 0 && (
              <div className="flex items-center gap-1.5 ml-auto">
                <select
                  value={bulkSkuId}
                  onChange={(e) => setBulkSkuId(e.target.value)}
                  className="px-2 py-1.5 border border-slate-300 rounded-md text-xs bg-white"
                >
                  <option value="">Select license SKU...</option>
                  {skus.map((sku) => (
                    <option key={sku.skuId} value={sku.skuId}>
                      {sku.skuPartNumber}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  disabled={!bulkSkuId || bulkLicenseMutation.isPending}
                  onClick={() => bulkLicenseMutation.mutate('assign')}
                  className="px-2.5 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-700 text-white font-medium disabled:opacity-40 cursor-pointer"
                >
                  Assign SKU
                </button>
                <button
                  type="button"
                  disabled={!bulkSkuId || bulkLicenseMutation.isPending}
                  onClick={() => bulkLicenseMutation.mutate('remove')}
                  className="px-2.5 py-1.5 rounded-md bg-slate-700 hover:bg-slate-800 text-white font-medium disabled:opacity-40 cursor-pointer"
                >
                  Remove SKU
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          {usersQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-slate-500">
              Loading directory users...
            </div>
          ) : usersQuery.error ? (
            <div className="p-6 text-sm text-rose-700 bg-rose-50">
              {usersQuery.error instanceof Error
                ? usersQuery.error.message
                : 'Failed to load users.'}
            </div>
          ) : (usersQuery.data?.users.length ?? 0) === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No users found.
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      {isAdmin && <th className="px-4 py-3 w-8" />}
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Licenses</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {usersQuery.data!.users.map((user) => {
                      const active = selectedUserId === user.id
                      return (
                        <tr
                          key={user.id}
                          onClick={() => setSelectedUserId(user.id)}
                          className={`cursor-pointer transition-colors ${
                            active ? 'bg-indigo-50/70' : 'hover:bg-slate-50'
                          }`}
                        >
                          {isAdmin && (
                            <td
                              className="px-4 py-3"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <input
                                type="checkbox"
                                checked={checkedIds.includes(user.id)}
                                onChange={() => toggleChecked(user.id)}
                                className="rounded border-slate-300"
                              />
                            </td>
                          )}
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-900">
                              {user.displayName}
                            </div>
                            <div className="text-xs text-slate-500">
                              {user.userPrincipalName}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {user.accountEnabled ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                                <CheckCircle2 className="h-3 w-3" />
                                Enabled
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-rose-50 text-rose-700 border border-rose-200">
                                <XCircle className="h-3 w-3" />
                                Disabled
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-600">
                            {user.assignedLicenses.length === 0 ? (
                              <span className="text-slate-400">Unlicensed</span>
                            ) : (
                              <div className="flex flex-wrap gap-1">
                                {user.assignedLicenses.slice(0, 2).map((lic) => (
                                  <span
                                    key={lic.skuId}
                                    className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[11px]"
                                  >
                                    {skuNameById.get(lic.skuId) ??
                                      lic.skuId.slice(0, 8)}
                                  </span>
                                ))}
                                {user.assignedLicenses.length > 2 && (
                                  <span className="text-slate-400">
                                    +{user.assignedLicenses.length - 2}
                                  </span>
                                )}
                              </div>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              {usersQuery.data?.nextLink && (
                <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
                  <button
                    type="button"
                    onClick={() =>
                      setNextLink(usersQuery.data?.nextLink ?? undefined)
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

        {/* User Inspector Panel */}
        <aside className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-5">
          {!selectedUserId ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Select a user to inspect account attributes and licenses.
            </div>
          ) : detailQuery.isLoading ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Loading user details...
            </div>
          ) : detailQuery.error || !detailQuery.data ? (
            <div className="text-sm text-rose-700">
              {detailQuery.error instanceof Error
                ? detailQuery.error.message
                : 'Could not load user detail.'}
            </div>
          ) : (
            (() => {
              const user = detailQuery.data.user
              const assignedSet = new Set(
                user.assignedLicenses.map((l) => l.skuId),
              )
              return (
                <>
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      {user.displayName}
                    </h2>
                    <p className="text-xs text-slate-500 break-all">
                      {user.userPrincipalName}
                    </p>
                  </div>

                  <dl className="grid grid-cols-2 gap-3 text-xs border-t border-slate-100 pt-4">
                    <div>
                      <dt className="text-slate-500">Account State</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {user.accountEnabled ? 'Enabled' : 'Disabled'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Department</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {user.department || '—'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Job Title</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {user.jobTitle || '—'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Office</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {user.officeLocation || '—'}
                      </dd>
                    </div>
                  </dl>

                  {isAdmin && (
                    <div className="border-t border-slate-100 pt-4">
                      <button
                        type="button"
                        disabled={toggleMutation.isPending}
                        onClick={() =>
                          toggleMutation.mutate({
                            userId: user.id,
                            userPrincipalName: user.userPrincipalName,
                            accountEnabled: !user.accountEnabled,
                          })
                        }
                        className={`w-full inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium text-white transition-colors cursor-pointer disabled:opacity-50 ${
                          user.accountEnabled
                            ? 'bg-rose-600 hover:bg-rose-700'
                            : 'bg-emerald-600 hover:bg-emerald-700'
                        }`}
                      >
                        {user.accountEnabled ? (
                          <>
                            <UserX className="h-4 w-4" />
                            Disable Account
                          </>
                        ) : (
                          <>
                            <UserCheck className="h-4 w-4" />
                            Enable Account
                          </>
                        )}
                      </button>
                    </div>
                  )}

                  <div className="border-t border-slate-100 pt-4 space-y-2.5">
                    <div className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                      <KeyRound className="h-3.5 w-3.5 text-indigo-600" />
                      License Assignments
                    </div>
                    {detailQuery.data.subscribedSkus.length === 0 ? (
                      <p className="text-xs text-slate-500">
                        No tenant SKUs found.
                      </p>
                    ) : (
                      <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                        {detailQuery.data.subscribedSkus.map((sku) => {
                          const assigned = assignedSet.has(sku.skuId)
                          const available = Math.max(
                            0,
                            sku.prepaidUnits.enabled - sku.consumedUnits,
                          )
                          return (
                            <div
                              key={sku.skuId}
                              className="flex items-center justify-between gap-2 p-2.5 rounded-lg border border-slate-200 text-xs"
                            >
                              <div className="min-w-0">
                                <div className="font-medium text-slate-900 truncate">
                                  {sku.skuPartNumber}
                                </div>
                                <div className="text-[11px] text-slate-500">
                                  {available} available
                                </div>
                              </div>
                              {isAdmin ? (
                                <button
                                  type="button"
                                  disabled={licenseMutation.isPending}
                                  onClick={() =>
                                    licenseMutation.mutate({
                                      userId: user.id,
                                      userPrincipalName: user.userPrincipalName,
                                      addSkuIds: assigned ? [] : [sku.skuId],
                                      removeSkuIds: assigned ? [sku.skuId] : [],
                                    })
                                  }
                                  className={`px-2.5 py-1 rounded-md font-medium shrink-0 cursor-pointer disabled:opacity-50 ${
                                    assigned
                                      ? 'bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100'
                                      : 'bg-indigo-50 text-indigo-700 border border-indigo-200 hover:bg-indigo-100'
                                  }`}
                                >
                                  {assigned ? 'Remove' : 'Assign'}
                                </button>
                              ) : (
                                <span
                                  className={`px-2 py-0.5 rounded-full text-[11px] font-medium ${
                                    assigned
                                      ? 'bg-emerald-50 text-emerald-700'
                                      : 'bg-slate-100 text-slate-500'
                                  }`}
                                >
                                  {assigned ? 'Assigned' : 'Not assigned'}
                                </span>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>

                  {/* Recent Sign-in Activity for this user */}
                  <div className="border-t border-slate-100 pt-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-700">
                        Recent Sign-ins
                      </span>
                      <Link
                        to="/signins"
                        search={{ user: user.userPrincipalName }}
                        className="text-[11px] font-medium text-indigo-600 hover:text-indigo-700"
                      >
                        Troubleshoot all &rarr;
                      </Link>
                    </div>
                    {userSignInsQuery.isLoading ? (
                      <p className="text-xs text-slate-400">
                        Loading recent sign-ins...
                      </p>
                    ) : userSignInsQuery.data && !userSignInsQuery.data.ok ? (
                      <p className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-lg p-2">
                        {userSignInsQuery.data.error?.title}: grant{' '}
                        <code className="font-mono">AuditLog.Read.All</code> to
                        view sign-in logs.
                      </p>
                    ) : (userSignInsQuery.data?.signIns.length ?? 0) === 0 ? (
                      <p className="text-xs text-slate-500">
                        No recent sign-in logs found in retention window.
                      </p>
                    ) : (
                      <div className="space-y-1.5">
                        {userSignInsQuery.data!.signIns.map((s) => {
                          const ok = (s.status?.errorCode ?? 0) === 0
                          return (
                            <div
                              key={s.id}
                              className="p-2 rounded-lg border border-slate-200 text-[11px] flex items-center justify-between gap-2"
                            >
                              <div className="min-w-0">
                                <div className="font-medium text-slate-800 truncate">
                                  {s.appDisplayName || 'Unknown App'}
                                </div>
                                <div className="text-slate-500 truncate">
                                  {new Date(s.createdDateTime).toLocaleString()}{' '}
                                  • {s.ipAddress || '—'}
                                </div>
                              </div>
                              <span
                                title={s.diagnosis.title}
                                className={`px-1.5 py-0.5 rounded font-mono font-semibold shrink-0 ${
                                  ok
                                    ? 'bg-emerald-50 text-emerald-700'
                                    : 'bg-rose-50 text-rose-700'
                                }`}
                              >
                                {ok ? 'OK' : s.diagnosis.aadstsCode}
                              </span>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                </>
              )
            })()
          )}
        </aside>
      </div>
    </div>
  )
}
