import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  RefreshCw,
  Search,
  Trash2,
  UserPlus,
  UsersRound,
} from 'lucide-react'
import { useState } from 'react'
import {
  addGroupMemberFn,
  getGroupDetailFn,
  listGroupsFn,
  removeGroupMemberFn,
  searchDirectoryUsersFn,
} from '~/server/functions/groups'

export const Route = createFileRoute('/groups')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Groups — Pocket365' }],
  }),
  component: GroupsPage,
})

function groupKindLabel(group: {
  groupTypes: string[]
  securityEnabled: boolean
  mailEnabled: boolean
}): string {
  if (group.groupTypes.includes('Unified')) return 'Microsoft 365'
  if (group.securityEnabled && group.mailEnabled) return 'Mail-Enabled Security'
  if (group.securityEnabled) return 'Security'
  return 'Distribution'
}

function GroupsPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [searchInput, setSearchInput] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [nextLink, setNextLink] = useState<string | undefined>(undefined)
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null)
  const [memberSearch, setMemberSearch] = useState('')
  const [feedback, setFeedback] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const groupsQuery = useQuery({
    queryKey: ['groups', appliedSearch, nextLink],
    queryFn: () =>
      listGroupsFn({
        data: {
          search: appliedSearch || undefined,
          nextLink,
        },
      }),
  })

  const detailQuery = useQuery({
    queryKey: ['group-detail', selectedGroupId],
    enabled: Boolean(selectedGroupId),
    queryFn: () => getGroupDetailFn({ data: { groupId: selectedGroupId! } }),
  })

  const userLookupQuery = useQuery({
    queryKey: ['group-user-search', memberSearch],
    enabled: isAdmin && memberSearch.trim().length >= 2,
    queryFn: () =>
      searchDirectoryUsersFn({ data: { query: memberSearch.trim() } }),
  })

  const addMemberMutation = useMutation({
    mutationFn: (params: {
      groupId: string
      groupDisplayName: string
      memberId: string
      memberLabel: string
    }) => addGroupMemberFn({ data: params }),
    onSuccess: (_res, vars) => {
      setFeedback({
        type: 'success',
        text: `Added ${vars.memberLabel} to ${vars.groupDisplayName}.`,
      })
      setMemberSearch('')
      queryClient.invalidateQueries({
        queryKey: ['group-detail', vars.groupId],
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to add member.',
      })
    },
  })

  const removeMemberMutation = useMutation({
    mutationFn: (params: {
      groupId: string
      groupDisplayName: string
      memberId: string
      memberLabel: string
    }) => removeGroupMemberFn({ data: params }),
    onSuccess: (_res, vars) => {
      setFeedback({
        type: 'success',
        text: `Removed ${vars.memberLabel} from ${vars.groupDisplayName}.`,
      })
      queryClient.invalidateQueries({
        queryKey: ['group-detail', vars.groupId],
      })
    },
    onError: (err) => {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to remove member.',
      })
    },
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Groups & Memberships
          </h1>
          <p className="text-sm text-slate-600">
            Inspect Entra ID security and Microsoft 365 groups and manage
            membership assignments.
          </p>
        </div>
        <button
          type="button"
          onClick={() => groupsQuery.refetch()}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${groupsQuery.isFetching ? 'animate-spin' : ''}`}
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
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
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
              placeholder="Search groups by name or email..."
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
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          {groupsQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-slate-500">
              Loading directory groups...
            </div>
          ) : groupsQuery.error ? (
            <div className="p-6 text-sm text-rose-700 bg-rose-50">
              {groupsQuery.error instanceof Error
                ? groupsQuery.error.message
                : 'Failed to load groups.'}
            </div>
          ) : (groupsQuery.data?.groups.length ?? 0) === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              No groups found.
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Group</th>
                      <th className="px-4 py-3">Type</th>
                      <th className="px-4 py-3">Mail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {groupsQuery.data!.groups.map((group) => {
                      const active = selectedGroupId === group.id
                      return (
                        <tr
                          key={group.id}
                          onClick={() => setSelectedGroupId(group.id)}
                          className={`cursor-pointer transition-colors ${
                            active ? 'bg-indigo-50/70' : 'hover:bg-slate-50'
                          }`}
                        >
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-900">
                              {group.displayName}
                            </div>
                            {group.description && (
                              <div className="text-xs text-slate-500 line-clamp-1">
                                {group.description}
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                              {groupKindLabel(group)}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-600">
                            {group.mail || '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              {groupsQuery.data?.nextLink && (
                <div className="px-4 py-3 border-t border-slate-200 bg-slate-50 flex justify-end">
                  <button
                    type="button"
                    onClick={() =>
                      setNextLink(groupsQuery.data?.nextLink ?? undefined)
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

        {/* Group Detail Inspector */}
        <aside className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-5">
          {!selectedGroupId ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Select a group to inspect members.
            </div>
          ) : detailQuery.isLoading ? (
            <div className="text-sm text-slate-500 py-8 text-center">
              Loading group members...
            </div>
          ) : detailQuery.error || !detailQuery.data ? (
            <div className="text-sm text-rose-700">
              {detailQuery.error instanceof Error
                ? detailQuery.error.message
                : 'Could not load group details.'}
            </div>
          ) : (
            (() => {
              const { group, members } = detailQuery.data
              const existingMemberIds = new Set(members.map((m) => m.id))

              return (
                <>
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      {group.displayName}
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      {group.description || groupKindLabel(group)}
                    </p>
                    <p className="text-[11px] font-mono text-slate-400 mt-1">
                      ID: {group.id}
                    </p>
                  </div>

                  {isAdmin && (
                    <div className="border-t border-slate-100 pt-4 space-y-2">
                      <label className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                        <UserPlus className="h-3.5 w-3.5 text-indigo-600" />
                        Add Member
                      </label>
                      <input
                        type="text"
                        value={memberSearch}
                        onChange={(e) => setMemberSearch(e.target.value)}
                        placeholder="Type 2+ chars to search users..."
                        className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg"
                      />
                      {userLookupQuery.data &&
                        userLookupQuery.data.users.length > 0 && (
                          <div className="border border-slate-200 rounded-lg divide-y divide-slate-100 max-h-44 overflow-y-auto">
                            {userLookupQuery.data.users.map((u) => {
                              const alreadyMember = existingMemberIds.has(u.id)
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
                                    disabled={
                                      alreadyMember ||
                                      addMemberMutation.isPending
                                    }
                                    onClick={() =>
                                      addMemberMutation.mutate({
                                        groupId: group.id,
                                        groupDisplayName: group.displayName,
                                        memberId: u.id,
                                        memberLabel: u.userPrincipalName,
                                      })
                                    }
                                    className="px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-medium disabled:opacity-40 cursor-pointer shrink-0"
                                  >
                                    {alreadyMember ? 'Member' : 'Add'}
                                  </button>
                                </div>
                              )
                            })}
                          </div>
                        )}
                    </div>
                  )}

                  <div className="border-t border-slate-100 pt-4 space-y-2">
                    <div className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                      <UsersRound className="h-3.5 w-3.5 text-indigo-600" />
                      Members ({members.length})
                    </div>
                    {members.length === 0 ? (
                      <p className="text-xs text-slate-500">
                        This group has no direct members.
                      </p>
                    ) : (
                      <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                        {members.map((member) => (
                          <div
                            key={member.id}
                            className="flex items-center justify-between gap-2 p-2.5 rounded-lg border border-slate-200 text-xs"
                          >
                            <div className="min-w-0">
                              <div className="font-medium text-slate-900 truncate">
                                {member.displayName}
                              </div>
                              <div className="text-[11px] text-slate-500 truncate">
                                {member.userPrincipalName ||
                                  member.mail ||
                                  member.id}
                              </div>
                            </div>
                            {isAdmin && (
                              <button
                                type="button"
                                title="Remove member"
                                disabled={removeMemberMutation.isPending}
                                onClick={() =>
                                  removeMemberMutation.mutate({
                                    groupId: group.id,
                                    groupDisplayName: group.displayName,
                                    memberId: member.id,
                                    memberLabel:
                                      member.userPrincipalName ||
                                      member.displayName,
                                  })
                                }
                                className="p-1.5 rounded-md text-rose-600 hover:bg-rose-50 disabled:opacity-40 cursor-pointer"
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
              )
            })()
          )}
        </aside>
      </div>
    </div>
  )
}
