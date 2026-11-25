import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  CheckCircle2,
  Mail,
  Save,
  Search,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  deleteInboxRuleFn,
  getMailboxAuditFn,
  updateMailboxAutoReplyFn,
} from '~/server/functions/mailboxes'
import { listUsersFn } from '~/server/functions/users'

export const Route = createFileRoute('/mailboxes')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Mailbox Security & Settings — Pocket365' }],
  }),
  component: MailboxesPage,
})

function MailboxesPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [searchInput, setSearchInput] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [selectedUser, setSelectedUser] = useState<{
    id: string
    displayName: string
    userPrincipalName: string
  } | null>(null)

  const [oofStatus, setOofStatus] = useState<
    'disabled' | 'alwaysEnabled' | 'scheduled'
  >('disabled')
  const [externalAudience, setExternalAudience] = useState<
    'none' | 'contactsOnly' | 'all'
  >('all')
  const [internalMessage, setInternalMessage] = useState('')
  const [externalMessage, setExternalMessage] = useState('')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const usersQuery = useQuery({
    queryKey: ['mailbox-users', appliedSearch],
    queryFn: () =>
      listUsersFn({
        data: { search: appliedSearch || undefined, top: 30 },
      }),
  })

  const mailboxQuery = useQuery({
    queryKey: ['mailbox-audit', selectedUser?.id],
    enabled: Boolean(selectedUser?.id),
    queryFn: () => getMailboxAuditFn({ data: { userId: selectedUser!.id } }),
  })

  useEffect(() => {
    const ar = mailboxQuery.data?.settings?.automaticRepliesSetting
    if (ar) {
      setOofStatus(ar.status || 'disabled')
      setExternalAudience(ar.externalAudience || 'all')
      setInternalMessage(ar.internalReplyMessage || '')
      setExternalMessage(ar.externalReplyMessage || '')
    }
  }, [mailboxQuery.data?.settings])

  const saveOofMutation = useMutation({
    mutationFn: () =>
      updateMailboxAutoReplyFn({
        data: {
          userId: selectedUser!.id,
          userPrincipalName: selectedUser!.userPrincipalName,
          status: oofStatus,
          externalAudience,
          internalReplyMessage: internalMessage,
          externalReplyMessage: externalMessage,
        },
      }),
    onSuccess: () => {
      setBanner({
        type: 'success',
        text: `Updated Out-of-Office settings for ${selectedUser?.userPrincipalName}.`,
      })
      queryClient.invalidateQueries({
        queryKey: ['mailbox-audit', selectedUser?.id],
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Failed to update Out-of-Office settings.',
      })
    },
  })

  const deleteRuleMutation = useMutation({
    mutationFn: (vars: { ruleId: string; ruleDisplayName: string }) =>
      deleteInboxRuleFn({
        data: {
          userId: selectedUser!.id,
          userPrincipalName: selectedUser!.userPrincipalName,
          ruleId: vars.ruleId,
          ruleDisplayName: vars.ruleDisplayName,
        },
      }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Deleted inbox rule "${vars.ruleDisplayName}".`,
      })
      queryClient.invalidateQueries({
        queryKey: ['mailbox-audit', selectedUser?.id],
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to delete rule.',
      })
    },
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Mailbox Security & Settings
        </h1>
        <p className="text-sm text-slate-600">
          Inspect Exchange Online inbox rules for BEC external forwarding or
          stealth deletion indicators, and configure Out-of-Office automatic
          replies.
        </p>
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* User Picker */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="p-3 border-b border-slate-200">
            <form
              className="flex gap-1.5"
              onSubmit={(e) => {
                e.preventDefault()
                setAppliedSearch(searchInput.trim())
              }}
            >
              <div className="relative flex-1">
                <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Find mailbox user..."
                  className="w-full pl-8 pr-2.5 py-1.5 text-xs border border-slate-300 rounded-lg"
                />
              </div>
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
              >
                Go
              </button>
            </form>
          </div>
          <div className="divide-y divide-slate-100 max-h-[34rem] overflow-y-auto">
            {usersQuery.isLoading ? (
              <div className="p-6 text-center text-xs text-slate-500">
                Loading users...
              </div>
            ) : (usersQuery.data?.users ?? []).map((u) => {
                const active = selectedUser?.id === u.id
                return (
                  <button
                    key={u.id}
                    type="button"
                    onClick={() =>
                      setSelectedUser({
                        id: u.id,
                        displayName: u.displayName,
                        userPrincipalName: u.userPrincipalName,
                      })
                    }
                    className={`w-full text-left px-4 py-3 text-xs cursor-pointer transition-colors ${
                      active ? 'bg-indigo-50/80' : 'hover:bg-slate-50'
                    }`}
                  >
                    <div className="font-medium text-slate-900 truncate">
                      {u.displayName}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate">
                      {u.userPrincipalName}
                    </div>
                  </button>
                )
              })}
          </div>
        </div>

        {/* Mailbox Audit & Auto-Reply Panel */}
        <div className="lg:col-span-2 space-y-6">
          {!selectedUser ? (
            <div className="bg-white rounded-xl border border-slate-200 p-10 text-center text-sm text-slate-500">
              Select a user on the left to audit inbox forwarding rules and
              Out-of-Office settings.
            </div>
          ) : mailboxQuery.isLoading ? (
            <div className="bg-white rounded-xl border border-slate-200 p-10 text-center text-sm text-slate-500">
              Loading mailbox rules and settings for {selectedUser.displayName}...
            </div>
          ) : (
            <>
              {/* Inbox Rules (BEC / Forwarding Audit) */}
              <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-indigo-600" />
                    Inbox Rules & Forwarding Check — {selectedUser.displayName}
                  </h2>
                  <span className="text-xs text-slate-500">
                    {mailboxQuery.data?.rules.length ?? 0} rule(s)
                  </span>
                </div>

                <div className="p-5 space-y-3">
                  {mailboxQuery.data?.rulesError ? (
                    <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 text-xs text-amber-950 space-y-1">
                      <div className="font-semibold flex items-center gap-1.5">
                        <AlertTriangle className="h-4 w-4 text-amber-600" />
                        {mailboxQuery.data.rulesError.title}
                      </div>
                      <p>{mailboxQuery.data.rulesError.message}</p>
                      <p>
                        Grant <code className="font-mono">Mail.ReadWrite</code>{' '}
                        application permission with Admin Consent.
                      </p>
                    </div>
                  ) : (mailboxQuery.data?.rules.length ?? 0) === 0 ? (
                    <div className="flex items-center gap-2 text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      No inbox rules configured (no suspicious forwarding rules
                      detected).
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {mailboxQuery.data!.rules.map((rule) => (
                        <div
                          key={rule.id}
                          className={`rounded-lg border p-3.5 text-xs space-y-1.5 ${
                            rule.riskLevel === 'high'
                              ? 'bg-rose-50/70 border-rose-200'
                              : rule.riskLevel === 'medium'
                                ? 'bg-amber-50/70 border-amber-200'
                                : 'bg-white border-slate-200'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-900">
                                {rule.displayName}
                              </span>
                              <span
                                className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                                  rule.riskLevel === 'high'
                                    ? 'bg-rose-100 text-rose-800'
                                    : rule.riskLevel === 'medium'
                                      ? 'bg-amber-100 text-amber-900'
                                      : 'bg-slate-100 text-slate-600'
                                }`}
                              >
                                {rule.riskLevel} risk
                              </span>
                              {!rule.isEnabled && (
                                <span className="text-[10px] text-slate-500">
                                  (disabled)
                                </span>
                              )}
                            </div>
                            {isAdmin && (
                              <button
                                type="button"
                                disabled={deleteRuleMutation.isPending}
                                onClick={() =>
                                  deleteRuleMutation.mutate({
                                    ruleId: rule.id,
                                    ruleDisplayName: rule.displayName,
                                  })
                                }
                                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white text-[11px] font-medium cursor-pointer"
                              >
                                <Trash2 className="h-3 w-3" />
                                Delete Rule
                              </button>
                            )}
                          </div>
                          <div className="text-slate-700">
                            Actions: {rule.actionsSummary.join(' • ')}
                          </div>
                          {rule.riskReasons.length > 0 && (
                            <div className="text-rose-800 font-medium">
                              {rule.riskReasons.join(' — ')}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>

              {/* Out-of-Office (Automatic Replies) */}
              <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                    <Mail className="h-4 w-4 text-indigo-600" />
                    Out-of-Office / Automatic Replies
                  </h2>
                  {mailboxQuery.data?.settings?.timeZone && (
                    <span className="text-xs text-slate-500">
                      TZ: {mailboxQuery.data.settings.timeZone}
                    </span>
                  )}
                </div>

                <div className="p-5 space-y-4 text-xs">
                  {mailboxQuery.data?.settingsError ? (
                    <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 text-amber-950 space-y-1">
                      <div className="font-semibold">
                        {mailboxQuery.data.settingsError.title}
                      </div>
                      <p>{mailboxQuery.data.settingsError.message}</p>
                      <p>
                        Grant{' '}
                        <code className="font-mono">
                          MailboxSettings.ReadWrite
                        </code>{' '}
                        with Admin Consent.
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <label className="space-y-1 block">
                          <span className="font-medium text-slate-700">
                            Auto-Reply Status
                          </span>
                          <select
                            disabled={!isAdmin}
                            value={oofStatus}
                            onChange={(e) =>
                              setOofStatus(
                                e.target.value as
                                  | 'disabled'
                                  | 'alwaysEnabled'
                                  | 'scheduled',
                              )
                            }
                            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white disabled:bg-slate-50"
                          >
                            <option value="disabled">Disabled</option>
                            <option value="alwaysEnabled">
                              Always Enabled
                            </option>
                            <option value="scheduled">Scheduled</option>
                          </select>
                        </label>
                        <label className="space-y-1 block">
                          <span className="font-medium text-slate-700">
                            External Audience
                          </span>
                          <select
                            disabled={!isAdmin}
                            value={externalAudience}
                            onChange={(e) =>
                              setExternalAudience(
                                e.target.value as
                                  | 'none'
                                  | 'contactsOnly'
                                  | 'all',
                              )
                            }
                            className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white disabled:bg-slate-50"
                          >
                            <option value="all">All External Senders</option>
                            <option value="contactsOnly">Contacts Only</option>
                            <option value="none">Internal Only (None)</option>
                          </select>
                        </label>
                      </div>

                      <label className="space-y-1 block">
                        <span className="font-medium text-slate-700">
                          Internal Reply Message
                        </span>
                        <textarea
                          rows={3}
                          disabled={!isAdmin}
                          value={internalMessage}
                          onChange={(e) => setInternalMessage(e.target.value)}
                          placeholder="I am currently out of the office..."
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg disabled:bg-slate-50"
                        />
                      </label>

                      <label className="space-y-1 block">
                        <span className="font-medium text-slate-700">
                          External Reply Message
                        </span>
                        <textarea
                          rows={3}
                          disabled={!isAdmin}
                          value={externalMessage}
                          onChange={(e) => setExternalMessage(e.target.value)}
                          placeholder="Thank you for your email..."
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg disabled:bg-slate-50"
                        />
                      </label>

                      {isAdmin && (
                        <button
                          type="button"
                          disabled={saveOofMutation.isPending}
                          onClick={() => saveOofMutation.mutate()}
                          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
                        >
                          <Save className="h-3.5 w-3.5" />
                          {saveOofMutation.isPending
                            ? 'Saving...'
                            : 'Save Automatic Replies'}
                        </button>
                      )}
                    </>
                  )}
                </div>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
