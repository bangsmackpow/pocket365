import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  Bell,
  Play,
  Plus,
  RefreshCw,
  Send,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import {
  addAlertWebhookFn,
  deleteAlertWebhookFn,
  getAlertsDashboardFn,
  runAlertChecksNowFn,
  sendTestAlertFn,
  toggleAlertWebhookFn,
} from '~/server/functions/alerts'
import type { WebhookProvider } from '~/server/db/schema'

export const Route = createFileRoute('/alerts')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Security Alerts — Pocket365' }],
  }),
  component: AlertsPage,
})

function AlertsPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [name, setName] = useState('')
  const [provider, setProvider] = useState<WebhookProvider>('teams')
  const [url, setUrl] = useState('')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const query = useQuery({
    queryKey: ['alerts-dashboard'],
    queryFn: () => getAlertsDashboardFn(),
  })

  const addMutation = useMutation({
    mutationFn: () => addAlertWebhookFn({ data: { name, provider, url } }),
    onSuccess: () => {
      setName('')
      setUrl('')
      setBanner({ type: 'success', text: 'Webhook destination saved.' })
      queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save webhook.',
      })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (vars: { id: string; enabled: boolean }) =>
      toggleAlertWebhookFn({ data: vars }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteAlertWebhookFn({ data: { id } }),
    onSuccess: () => {
      setBanner({ type: 'success', text: 'Webhook deleted.' })
      queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
    },
  })

  const testMutation = useMutation({
    mutationFn: () => sendTestAlertFn(),
    onSuccess: (res) => {
      setBanner({
        type: res.deliveryStatus === 'failed' ? 'error' : 'success',
        text: `Test notification completed (status: ${res.deliveryStatus}).`,
      })
      queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to send test alert.',
      })
    },
  })

  const runNowMutation = useMutation({
    mutationFn: () => runAlertChecksNowFn(),
    onSuccess: (res) => {
      setBanner({
        type: 'success',
        text: `Checked ${res.rulesEvaluated.length} rule(s): ${res.alertsTriggered} new alert(s) triggered, ${res.alertsSkippedDedupe} deduplicated.`,
      })
      queryClient.invalidateQueries({ queryKey: ['alerts-dashboard'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to run checks.',
      })
    },
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Automated Security & Drift Alerts
          </h1>
          <p className="text-sm text-slate-600">
            Receive Teams, Slack, Discord, or webhook alerts on Global Admin
            changes, CIS regressions, expiring app secrets, and Smart Lockout
            spikes (runs automatically every 30 minutes).
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isAdmin && (
            <>
              <button
                type="button"
                disabled={testMutation.isPending}
                onClick={() => testMutation.mutate()}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
              >
                <Send className="h-3.5 w-3.5" />
                Send Test Alert
              </button>
              <button
                type="button"
                disabled={runNowMutation.isPending}
                onClick={() => runNowMutation.mutate()}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
              >
                <Play className="h-3.5 w-3.5" />
                {runNowMutation.isPending ? 'Checking...' : 'Run Checks Now'}
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => query.refetch()}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${query.isFetching ? 'animate-spin' : ''}`}
            />
            Refresh
          </button>
        </div>
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

      {/* Active Rules Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
        {[
          [
            'Privileged Role Drift',
            'Alerts immediately when a user is added to Global Administrator or any directory role.',
          ],
          [
            'CIS Regressions',
            'Compares live tenant settings against your latest saved CIS snapshot to catch drift.',
          ],
          [
            'Expiring App Secrets',
            'Alerts when any Entra App Registration secret or certificate expires or is ≤ 30 days away.',
          ],
          [
            'Sign-in Lockout Spikes',
            'Detects Entra Smart Lockout (AADSTS50053) or ≥15 failed sign-ins within 60 minutes.',
          ],
        ].map(([title, desc]) => (
          <div
            key={title}
            className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-1"
          >
            <div className="font-semibold text-slate-900 flex items-center gap-1.5">
              <Bell className="h-3.5 w-3.5 text-indigo-600" />
              {title}
            </div>
            <p className="text-slate-600 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>

      {/* Webhook Destinations */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900">
            Webhook Destinations ({query.data?.webhooks.length ?? 0})
          </h2>
          <span className="text-xs text-slate-500">
            URLs stored encrypted/masked in SQLite
          </span>
        </div>

        <div className="p-5 space-y-4">
          {isAdmin && (
            <form
              className="grid grid-cols-1 md:grid-cols-6 gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                addMutation.mutate()
              }}
            >
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Name (e.g. IT Security Teams)"
                className="md:col-span-2 px-3 py-2 text-xs border border-slate-300 rounded-lg"
              />
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value as WebhookProvider)}
                className="px-3 py-2 text-xs border border-slate-300 rounded-lg bg-white"
              >
                <option value="teams">Microsoft Teams</option>
                <option value="slack">Slack</option>
                <option value="discord">Discord</option>
                <option value="generic">Generic JSON</option>
              </select>
              <input
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://..."
                className="md:col-span-2 px-3 py-2 text-xs border border-slate-300 rounded-lg"
              />
              <button
                type="submit"
                disabled={addMutation.isPending}
                className="inline-flex items-center justify-center gap-1 px-3 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </button>
            </form>
          )}

          {(query.data?.webhooks.length ?? 0) === 0 ? (
            <p className="text-xs text-slate-500">
              No webhooks configured yet. Alerts will still be recorded below
              when you run checks manually.
            </p>
          ) : (
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-lg">
              {query.data!.webhooks.map((w) => (
                <div
                  key={w.id}
                  className="px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-xs"
                >
                  <div>
                    <div className="font-semibold text-slate-900 flex items-center gap-2">
                      <span>{w.name}</span>
                      <span className="uppercase text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                        {w.provider}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-500 mt-0.5">
                      {w.maskedUrl}
                    </div>
                  </div>
                  {isAdmin && (
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          toggleMutation.mutate({
                            id: w.id,
                            enabled: !w.enabled,
                          })
                        }
                        className={`px-2.5 py-1 rounded-md font-medium cursor-pointer border ${
                          w.enabled
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-slate-100 text-slate-600 border-slate-200'
                        }`}
                      >
                        {w.enabled ? 'Enabled' : 'Paused'}
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteMutation.mutate(w.id)}
                        className="p-1.5 rounded text-rose-600 hover:bg-rose-50 cursor-pointer"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Alert History */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900">
            Recent Alert History ({query.data?.events.length ?? 0})
          </h2>
          <span className="text-xs text-slate-500">
            24-hour deduplication enabled
          </span>
        </div>
        {(query.data?.events.length ?? 0) === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No security alerts triggered yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Alert</th>
                  <th className="px-4 py-3">Delivery</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {query.data!.events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-50/70">
                    <td className="px-4 py-3 whitespace-nowrap text-slate-600">
                      {new Date(ev.createdAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                          ev.severity === 'critical'
                            ? 'bg-rose-100 text-rose-800'
                            : ev.severity === 'high'
                              ? 'bg-amber-100 text-amber-900'
                              : 'bg-sky-100 text-sky-800'
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-semibold text-slate-900">
                        {ev.title}
                      </div>
                      <div className="text-slate-600 mt-0.5">{ev.message}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-slate-600">
                      {ev.deliveryStatus}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
