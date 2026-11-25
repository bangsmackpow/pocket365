import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  CheckCircle2,
  Crown,
  RefreshCw,
  Trash2,
  UserPlus,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'
import {
  addRoleMemberFn,
  listPrivilegedRolesFn,
  removeRoleMemberFn,
} from '~/server/functions/governance'
import { searchDirectoryUsersFn } from '~/server/functions/groups'

export const Route = createFileRoute('/roles')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Privileged Roles — Pocket365' }],
  }),
  component: PrivilegedRolesPage,
})

function PrivilegedRolesPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [selectedRoleId, setSelectedRoleId] = useState<string | null>(null)
  const [userSearch, setUserSearch] = useState('')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const rolesQuery = useQuery({
    queryKey: ['privileged-roles'],
    queryFn: () => listPrivilegedRolesFn(),
  })

  const userLookupQuery = useQuery({
    queryKey: ['role-user-search', userSearch],
    enabled: isAdmin && userSearch.trim().length >= 2,
    queryFn: () =>
      searchDirectoryUsersFn({ data: { query: userSearch.trim() } }),
  })

  const addMutation = useMutation({
    mutationFn: (vars: {
      roleId: string
      roleDisplayName: string
      memberId: string
      memberLabel: string
    }) => addRoleMemberFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Assigned ${vars.memberLabel} to ${vars.roleDisplayName}.`,
      })
      setUserSearch('')
      queryClient.invalidateQueries({ queryKey: ['privileged-roles'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to assign role.',
      })
    },
  })

  const removeMutation = useMutation({
    mutationFn: (vars: {
      roleId: string
      roleDisplayName: string
      memberId: string
      memberLabel: string
    }) => removeRoleMemberFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Removed ${vars.memberLabel} from ${vars.roleDisplayName}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['privileged-roles'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to remove role.',
      })
    },
  })

  const roles = rolesQuery.data?.roles ?? []
  const selectedRole =
    roles.find((r) => r.id === selectedRoleId) ?? roles[0] ?? null
  const summary = rolesQuery.data?.summary

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Privileged Roles & Admin Monitor
          </h1>
          <p className="text-sm text-slate-600">
            Audit Entra ID directory role assignments, monitor Global Admin
            headcount, cross-check admin MFA status, and manage memberships.
          </p>
        </div>
        <button
          type="button"
          onClick={() => rolesQuery.refetch()}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${rolesQuery.isFetching ? 'animate-spin' : ''}`}
          />
          Refresh
        </button>
      </div>

      {rolesQuery.data && !rolesQuery.data.ok && rolesQuery.data.error && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-5 text-sm text-amber-950 space-y-2">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
            <span>{rolesQuery.data.error.title}</span>
          </div>
          <p className="text-xs">{rolesQuery.data.error.message}</p>
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

      {rolesQuery.data?.ok && summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MiniCard
            label="Global Administrators"
            value={String(summary.globalAdminCount)}
            sub="CIS recommends 2 to 4"
            tone={
              summary.globalAdminCount >= 2 && summary.globalAdminCount <= 4
                ? 'emerald'
                : 'rose'
            }
          />
          <MiniCard
            label="Unique Admin Accounts"
            value={String(summary.uniqueAdmins)}
            sub={`${summary.totalAssignments} total role assignment(s)`}
          />
          <MiniCard
            label="Active Roles"
            value={String(summary.activeRoles)}
            sub={`of ${roles.length} activated directory roles`}
          />
          <MiniCard
            label="Admins Missing MFA"
            value={String(summary.adminsMissingMfa)}
            sub="Cross-checked with MFA report"
            tone={summary.adminsMissingMfa > 0 ? 'rose' : 'emerald'}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Role List */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          {rolesQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-slate-500">
              Loading directory roles...
            </div>
          ) : roles.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No activated directory roles found.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                  <tr>
                    <th className="px-4 py-3">Directory Role</th>
                    <th className="px-4 py-3 w-28">Members</th>
                    <th className="px-4 py-3 w-36">MFA Health</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {roles.map((role) => {
                    const active = selectedRole?.id === role.id
                    const missingMfa = role.members.filter(
                      (m) => m.mfaRegistered === false,
                    ).length
                    const isGa =
                      role.displayName.toLowerCase() === 'global administrator'
                    return (
                      <tr
                        key={role.id}
                        onClick={() => setSelectedRoleId(role.id)}
                        className={`cursor-pointer transition-colors ${
                          active ? 'bg-indigo-50/70' : 'hover:bg-slate-50'
                        }`}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2 font-medium text-slate-900">
                            {isGa && (
                              <Crown className="h-4 w-4 text-amber-500 shrink-0" />
                            )}
                            <span>{role.displayName}</span>
                          </div>
                          {role.description && (
                            <div className="text-xs text-slate-500 line-clamp-1 mt-0.5">
                              {role.description}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-800">
                            {role.members.length}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {role.members.length === 0 ? (
                            <span className="text-slate-400">—</span>
                          ) : missingMfa > 0 ? (
                            <span className="inline-flex items-center gap-1 text-rose-700 font-semibold">
                              <XCircle className="h-3.5 w-3.5" />
                              {missingMfa} missing
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              OK
                            </span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Role Member Inspector */}
        <aside className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4">
          {!selectedRole ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Select a directory role to inspect assigned administrators.
            </div>
          ) : (
            <>
              <div>
                <h2 className="text-base font-semibold text-slate-900">
                  {selectedRole.displayName}
                </h2>
                {selectedRole.description && (
                  <p className="text-xs text-slate-500 mt-1">
                    {selectedRole.description}
                  </p>
                )}
              </div>

              {isAdmin && (
                <div className="border-t border-slate-100 pt-3 space-y-2">
                  <label className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                    <UserPlus className="h-3.5 w-3.5 text-indigo-600" />
                    Assign Administrator
                  </label>
                  <input
                    type="text"
                    value={userSearch}
                    onChange={(e) => setUserSearch(e.target.value)}
                    placeholder="Type 2+ chars to search users..."
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg"
                  />
                  {userLookupQuery.data &&
                    userLookupQuery.data.users.length > 0 && (
                      <div className="border border-slate-200 rounded-lg divide-y divide-slate-100 max-h-40 overflow-y-auto">
                        {userLookupQuery.data.users.map((u) => {
                          const exists = selectedRole.members.some(
                            (m) => m.id === u.id,
                          )
                          return (
                            <div
                              key={u.id}
                              className="px-3 py-2 flex items-center justify-between gap-2 text-xs"
                            >
                              <div className="min-w-0">
                                <div className="font-medium text-slate-900 truncate">
                                  {u.displayName}
                                </div>
                                <div className="text-[11px] text-slate-500 truncate">
                                  {u.userPrincipalName}
                                </div>
                              </div>
                              <button
                                type="button"
                                disabled={exists || addMutation.isPending}
                                onClick={() =>
                                  addMutation.mutate({
                                    roleId: selectedRole.id,
                                    roleDisplayName: selectedRole.displayName,
                                    memberId: u.id,
                                    memberLabel: u.userPrincipalName,
                                  })
                                }
                                className="px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-medium disabled:opacity-40 cursor-pointer shrink-0"
                              >
                                {exists ? 'Assigned' : 'Add'}
                              </button>
                            </div>
                          )
                        })}
                      </div>
                    )}
                </div>
              )}

              <div className="border-t border-slate-100 pt-3 space-y-2">
                <div className="text-xs font-semibold text-slate-700">
                  Assigned Members ({selectedRole.members.length})
                </div>
                {selectedRole.members.length === 0 ? (
                  <p className="text-xs text-slate-500">
                    No members currently assigned to this role.
                  </p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                    {selectedRole.members.map((m) => (
                      <div
                        key={m.id}
                        className="p-2.5 rounded-lg border border-slate-200 text-xs flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="font-medium text-slate-900 truncate">
                            {m.displayName}
                          </div>
                          <div className="text-[11px] text-slate-500 truncate">
                            {m.userPrincipalName || m.id}
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            {m.mfaRegistered === true && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold">
                                MFA OK
                              </span>
                            )}
                            {m.mfaRegistered === false && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 font-semibold">
                                NO MFA
                              </span>
                            )}
                            {m.userPrincipalName && (
                              <Link
                                to="/signins"
                                search={{ user: m.userPrincipalName }}
                                className="text-[10px] text-indigo-600 hover:underline"
                              >
                                Sign-ins
                              </Link>
                            )}
                          </div>
                        </div>

                        {isAdmin && (
                          <button
                            type="button"
                            title="Remove from role"
                            disabled={removeMutation.isPending}
                            onClick={() =>
                              removeMutation.mutate({
                                roleId: selectedRole.id,
                                roleDisplayName: selectedRole.displayName,
                                memberId: m.id,
                                memberLabel:
                                  m.userPrincipalName || m.displayName,
                              })
                            }
                            className="p-1.5 rounded text-rose-600 hover:bg-rose-50 disabled:opacity-40 cursor-pointer shrink-0"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </aside>
      </div>
    </div>
  )
}

function MiniCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string
  value: string
  sub: string
  tone?: 'emerald' | 'rose'
}) {
  const color =
    tone === 'rose'
      ? 'text-rose-700'
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
