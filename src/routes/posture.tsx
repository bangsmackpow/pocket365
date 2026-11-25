import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  AlertTriangle,
  Camera,
  CheckCircle2,
  KeyRound,
  Laptop,
  Lock,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
} from 'lucide-react'
import { useState } from 'react'
import {
  createCaSnapshotFn,
  getConditionalAccessDataFn,
  getDevicesAndBitlockerFn,
  getSecureScoreAndAlertsFn,
  listRiskyUsersFn,
  revealBitlockerKeyFn,
  runDeviceActionFn,
  runRiskyUserActionFn,
  setCaPolicyStateFn,
} from '~/server/functions/posture'
import type { FriendlyGraphError } from '~/server/graph/signin-errors'

export const Route = createFileRoute('/posture')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Security Posture & Devices — Pocket365' }],
  }),
  component: SecurityPosturePage,
})

function SecurityPosturePage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [tab, setTab] = useState<'score' | 'ca' | 'devices' | 'risky'>('score')
  const [snapshotLabel, setSnapshotLabel] = useState(
    `Baseline ${new Date().toISOString().slice(0, 10)}`,
  )
  const [revealedKey, setRevealedKey] = useState<{
    keyId: string
    deviceId: string | null
    value: string
  } | null>(null)
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const scoreQuery = useQuery({
    queryKey: ['secure-score-alerts'],
    enabled: tab === 'score',
    queryFn: () => getSecureScoreAndAlertsFn(),
  })

  const caQuery = useQuery({
    queryKey: ['conditional-access'],
    enabled: tab === 'ca',
    queryFn: () => getConditionalAccessDataFn(),
  })

  const devicesQuery = useQuery({
    queryKey: ['devices-bitlocker'],
    enabled: tab === 'devices',
    queryFn: () => getDevicesAndBitlockerFn(),
  })

  const riskyQuery = useQuery({
    queryKey: ['risky-users'],
    enabled: tab === 'risky',
    queryFn: () => listRiskyUsersFn(),
  })

  const snapshotMutation = useMutation({
    mutationFn: () =>
      createCaSnapshotFn({ data: { label: snapshotLabel.trim() || 'Snapshot' } }),
    onSuccess: (res) => {
      setBanner({
        type: 'success',
        text: `Saved Conditional Access baseline snapshot (${res.policyCount} policies) to SQLite.`,
      })
      queryClient.invalidateQueries({ queryKey: ['conditional-access'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save snapshot.',
      })
    },
  })

  const caStateMutation = useMutation({
    mutationFn: (vars: {
      policyId: string
      displayName: string
      state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced'
    }) => setCaPolicyStateFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Updated "${vars.displayName}" to ${vars.state}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['conditional-access'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to update CA policy.',
      })
    },
  })

  const deviceActionMutation = useMutation({
    mutationFn: (vars: {
      deviceId: string
      deviceName: string
      action: 'sync' | 'remote_lock'
    }) => runDeviceActionFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Sent ${vars.action.replace('_', ' ')} command to ${vars.deviceName}.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Device action failed.',
      })
    },
  })

  const bitlockerMutation = useMutation({
    mutationFn: (vars: { keyId: string; deviceId: string | null }) =>
      revealBitlockerKeyFn({ data: vars }),
    onSuccess: (res, vars) => {
      setRevealedKey({
        keyId: vars.keyId,
        deviceId: vars.deviceId,
        value: res.key,
      })
      setBanner({
        type: 'success',
        text: `BitLocker recovery key retrieved and recorded in SQLite audit log.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Failed to retrieve BitLocker recovery key.',
      })
    },
  })

  const riskyActionMutation = useMutation({
    mutationFn: (vars: {
      userId: string
      userPrincipalName: string
      action: 'confirm_compromised' | 'dismiss'
    }) => runRiskyUserActionFn({ data: vars }),
    onSuccess: (_res, vars) => {
      setBanner({
        type: 'success',
        text: `Executed ${vars.action.replace('_', ' ')} for ${vars.userPrincipalName}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['risky-users'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Risky user action failed.',
      })
    },
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Security Posture, Policies & Devices
          </h1>
          <p className="text-sm text-slate-600">
            Microsoft Secure Score, Defender alerts, Conditional Access policy
            drift detection, Intune devices, audited BitLocker keys, and
            Identity Protection.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            if (tab === 'score') scoreQuery.refetch()
            if (tab === 'ca') caQuery.refetch()
            if (tab === 'devices') devicesQuery.refetch()
            if (tab === 'risky') riskyQuery.refetch()
          }}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
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

      {/* Tabs */}
      <div className="border-b border-slate-200 flex flex-wrap gap-6">
        {(
          [
            ['score', 'Secure Score & Alerts', Radar],
            ['ca', 'Conditional Access & Drift', Shield],
            ['devices', 'Devices & BitLocker', Laptop],
            ['risky', 'Risky Users (P2)', ShieldAlert],
          ] as const
        ).map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer ${
              tab === id
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab 1: Secure Score & Alerts */}
      {tab === 'score' && (
        <div className="space-y-6">
          {scoreQuery.data?.scoreError && (
            <NoticeBanner error={scoreQuery.data.scoreError} />
          )}
          {scoreQuery.data?.secureScore && (
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <div className="text-xs uppercase font-semibold text-slate-500">
                    Microsoft Secure Score
                  </div>
                  <div className="text-3xl font-bold text-indigo-700 mt-1">
                    {Math.round(scoreQuery.data.secureScore.currentScore)} /{' '}
                    {Math.round(scoreQuery.data.secureScore.maxScore)}{' '}
                    <span className="text-lg text-slate-500">
                      (
                      {scoreQuery.data.secureScore.maxScore > 0
                        ? Math.round(
                            (scoreQuery.data.secureScore.currentScore /
                              scoreQuery.data.secureScore.maxScore) *
                              100,
                          )
                        : 0}
                      %)
                    </span>
                  </div>
                </div>
                <div className="text-xs text-slate-500">
                  Measured:{' '}
                  {new Date(
                    scoreQuery.data.secureScore.createdDateTime,
                  ).toLocaleString()}
                </div>
              </div>
              <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-indigo-600 rounded-full"
                  style={{
                    width: `${
                      scoreQuery.data.secureScore.maxScore > 0
                        ? Math.min(
                            100,
                            Math.round(
                              (scoreQuery.data.secureScore.currentScore /
                                scoreQuery.data.secureScore.maxScore) *
                                100,
                            ),
                          )
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>
          )}

          <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                Recent Security / Defender Alerts
              </h2>
              <span className="text-xs text-slate-500">
                {scoreQuery.data?.alerts.length ?? 0} alert(s)
              </span>
            </div>
            {scoreQuery.data?.alertsError ? (
              <div className="p-4">
                <NoticeBanner error={scoreQuery.data.alertsError} />
              </div>
            ) : (scoreQuery.data?.alerts.length ?? 0) === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500">
                No recent security alerts reported.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 text-xs">
                {scoreQuery.data!.alerts.map((a) => (
                  <div
                    key={a.id}
                    className="px-5 py-3 flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="font-medium text-slate-900">
                        {a.title}
                      </div>
                      <div className="text-slate-500">
                        {a.serviceSource || a.category || 'Security'} •{' '}
                        {new Date(a.createdDateTime).toLocaleString()}
                      </div>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase ${
                        a.severity === 'high'
                          ? 'bg-rose-50 text-rose-700'
                          : a.severity === 'medium'
                            ? 'bg-amber-50 text-amber-800'
                            : 'bg-slate-100 text-slate-700'
                      }`}
                    >
                      {a.severity} • {a.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {/* Tab 2: Conditional Access & Drift */}
      {tab === 'ca' && (
        <div className="space-y-5">
          {caQuery.data && !caQuery.data.ok && caQuery.data.error && (
            <NoticeBanner error={caQuery.data.error} />
          )}

          {caQuery.data?.ok && (
            <>
              {isAdmin && (
                <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap items-center gap-2 shadow-xs">
                  <input
                    type="text"
                    value={snapshotLabel}
                    onChange={(e) => setSnapshotLabel(e.target.value)}
                    placeholder="Baseline snapshot label..."
                    className="flex-1 min-w-52 px-3 py-2 text-xs border border-slate-300 rounded-lg"
                  />
                  <button
                    type="button"
                    disabled={snapshotMutation.isPending}
                    onClick={() => snapshotMutation.mutate()}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
                  >
                    <Camera className="h-3.5 w-3.5" />
                    Save SQLite Baseline Snapshot
                  </button>
                </div>
              )}

              {caQuery.data.drift && (
                <div
                  className={`rounded-xl border p-4 text-xs space-y-2 ${
                    caQuery.data.drift.hasDrift
                      ? 'bg-amber-50 border-amber-200 text-amber-950'
                      : 'bg-emerald-50 border-emerald-200 text-emerald-950'
                  }`}
                >
                  <div className="font-semibold flex items-center gap-2">
                    {caQuery.data.drift.hasDrift ? (
                      <AlertTriangle className="h-4 w-4 text-amber-600" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                    )}
                    <span>
                      Drift vs. Snapshot &ldquo;{caQuery.data.latestSnapshotLabel}&rdquo;:{' '}
                      {caQuery.data.drift.hasDrift
                        ? `${caQuery.data.drift.added} added, ${caQuery.data.drift.modified} modified, ${caQuery.data.drift.removed} removed`
                        : 'No configuration drift detected'}
                    </span>
                  </div>
                  {caQuery.data.drift.items.map((item) => (
                    <div
                      key={`${item.changeType}-${item.policyId}`}
                      className="pl-6"
                    >
                      <strong className="uppercase">[{item.changeType}]</strong>{' '}
                      {item.displayName}: {item.changes.join('; ')}
                    </div>
                  ))}
                </div>
              )}

              <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
                {caQuery.data.policies.length === 0 ? (
                  <div className="p-8 text-center text-sm text-slate-500">
                    No Conditional Access policies configured (on Entra Free,
                    Security Defaults provides baseline MFA protection).
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                        <tr>
                          <th className="px-4 py-3">Policy</th>
                          <th className="px-4 py-3">Grant Controls</th>
                          <th className="px-4 py-3">State</th>
                          {isAdmin && (
                            <th className="px-4 py-3 text-right">Change State</th>
                          )}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {caQuery.data.policies.map((pol) => (
                          <tr key={pol.id} className="hover:bg-slate-50/70">
                            <td className="px-4 py-3 font-medium text-slate-900">
                              {pol.displayName}
                            </td>
                            <td className="px-4 py-3 text-slate-600">
                              {pol.grantControls?.builtInControls?.join(', ') ||
                                '—'}
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                                  pol.state === 'enabled'
                                    ? 'bg-emerald-50 text-emerald-700'
                                    : pol.state === 'disabled'
                                      ? 'bg-rose-50 text-rose-700'
                                      : 'bg-amber-50 text-amber-800'
                                }`}
                              >
                                {pol.state === 'enabledForReportingButNotEnforced'
                                  ? 'Report-Only'
                                  : pol.state}
                              </span>
                            </td>
                            {isAdmin && (
                              <td className="px-4 py-3 text-right">
                                <select
                                  value={pol.state}
                                  disabled={caStateMutation.isPending}
                                  onChange={(e) =>
                                    caStateMutation.mutate({
                                      policyId: pol.id,
                                      displayName: pol.displayName,
                                      state: e.target.value as
                                        | 'enabled'
                                        | 'disabled'
                                        | 'enabledForReportingButNotEnforced',
                                    })
                                  }
                                  className="px-2 py-1 border border-slate-300 rounded bg-white text-xs"
                                >
                                  <option value="enabled">Enabled</option>
                                  <option value="enabledForReportingButNotEnforced">
                                    Report-Only
                                  </option>
                                  <option value="disabled">Disabled</option>
                                </select>
                              </td>
                            )}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* Tab 3: Intune Devices & BitLocker Keys */}
      {tab === 'devices' && (
        <div className="space-y-6">
          {revealedKey && (
            <div className="rounded-xl bg-indigo-50 border border-indigo-200 p-4 text-xs text-indigo-950 flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="font-semibold">
                  Audited BitLocker Recovery Key (Device:{' '}
                  {revealedKey.deviceId || revealedKey.keyId})
                </div>
                <div className="mt-1 font-mono text-base font-bold bg-white border border-indigo-200 px-3 py-1.5 rounded-lg inline-block select-all">
                  {revealedKey.value}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setRevealedKey(null)}
                className="underline cursor-pointer"
              >
                Clear
              </button>
            </div>
          )}

          {devicesQuery.data?.devicesError && (
            <NoticeBanner error={devicesQuery.data.devicesError} />
          )}

          <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                Intune Managed Devices ({devicesQuery.data?.devices.length ?? 0})
              </h2>
            </div>
            {(devicesQuery.data?.devices.length ?? 0) === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No Intune managed devices available.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                    <tr>
                      <th className="px-4 py-3">Device</th>
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">OS</th>
                      <th className="px-4 py-3">Compliance</th>
                      {isAdmin && <th className="px-4 py-3 text-right">Actions</th>}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {devicesQuery.data!.devices.map((d) => (
                      <tr key={d.id} className="hover:bg-slate-50/70">
                        <td className="px-4 py-3">
                          <div className="font-medium text-slate-900">
                            {d.deviceName || d.id}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {d.manufacturer} {d.model}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {d.userPrincipalName || '—'}
                        </td>
                        <td className="px-4 py-3 text-slate-600">
                          {d.operatingSystem} {d.osVersion}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                              d.complianceState === 'compliant'
                                ? 'bg-emerald-50 text-emerald-700'
                                : 'bg-amber-50 text-amber-800'
                            }`}
                          >
                            {d.complianceState || 'unknown'}
                          </span>
                        </td>
                        {isAdmin && (
                          <td className="px-4 py-3 text-right space-x-1.5 whitespace-nowrap">
                            <button
                              type="button"
                              disabled={deviceActionMutation.isPending}
                              onClick={() =>
                                deviceActionMutation.mutate({
                                  deviceId: d.id,
                                  deviceName: d.deviceName || d.id,
                                  action: 'sync',
                                })
                              }
                              className="px-2 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 cursor-pointer"
                            >
                              Sync
                            </button>
                            <button
                              type="button"
                              disabled={deviceActionMutation.isPending}
                              onClick={() =>
                                deviceActionMutation.mutate({
                                  deviceId: d.id,
                                  deviceName: d.deviceName || d.id,
                                  action: 'remote_lock',
                                })
                              }
                              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100 cursor-pointer"
                            >
                              <Lock className="h-3 w-3" />
                              Lock
                            </button>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-indigo-600" />
                BitLocker Recovery Keys (
                {devicesQuery.data?.bitlockerKeys.length ?? 0})
              </h2>
              <span className="text-xs text-slate-500">
                Every reveal is strictly audited in SQLite
              </span>
            </div>
            {devicesQuery.data?.bitlockerError ? (
              <div className="p-4">
                <NoticeBanner error={devicesQuery.data.bitlockerError} />
              </div>
            ) : (devicesQuery.data?.bitlockerKeys.length ?? 0) === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No BitLocker recovery keys stored in Entra ID.
              </div>
            ) : (
              <div className="divide-y divide-slate-100 text-xs">
                {devicesQuery.data!.bitlockerKeys.map((k) => (
                  <div
                    key={k.id}
                    className="px-5 py-3 flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="font-mono font-medium text-slate-900">
                        Device ID: {k.deviceId || 'Unknown'}
                      </div>
                      <div className="text-slate-500">
                        Key ID: {k.id} • Volume: {k.volumeType || 'OS'} •{' '}
                        {k.createdDateTime
                          ? new Date(k.createdDateTime).toLocaleDateString()
                          : ''}
                      </div>
                    </div>
                    {isAdmin && (
                      <button
                        type="button"
                        disabled={bitlockerMutation.isPending}
                        onClick={() =>
                          bitlockerMutation.mutate({
                            keyId: k.id,
                            deviceId: k.deviceId,
                          })
                        }
                        className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-medium cursor-pointer"
                      >
                        Reveal Key (Audited)
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {/* Tab 4: Risky Users (Entra ID P2) */}
      {tab === 'risky' && (
        <div className="space-y-4">
          {riskyQuery.data && !riskyQuery.data.ok && riskyQuery.data.error && (
            <NoticeBanner error={riskyQuery.data.error} />
          )}
          {riskyQuery.data?.ok && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
              {riskyQuery.data.users.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">
                  No risky users currently flagged by Entra ID Identity
                  Protection.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-slate-50 uppercase text-slate-500 border-b border-slate-200">
                      <tr>
                        <th className="px-4 py-3">User</th>
                        <th className="px-4 py-3">Risk Level</th>
                        <th className="px-4 py-3">Risk State</th>
                        <th className="px-4 py-3">Last Updated</th>
                        {isAdmin && (
                          <th className="px-4 py-3 text-right">Actions</th>
                        )}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {riskyQuery.data.users.map((u) => (
                        <tr key={u.id} className="hover:bg-slate-50/70">
                          <td className="px-4 py-3">
                            <div className="font-medium text-slate-900">
                              {u.userDisplayName}
                            </div>
                            <div className="text-slate-500">
                              {u.userPrincipalName}
                            </div>
                          </td>
                          <td className="px-4 py-3 uppercase font-semibold text-rose-700">
                            {u.riskLevel}
                          </td>
                          <td className="px-4 py-3">{u.riskState}</td>
                          <td className="px-4 py-3 text-slate-500">
                            {u.riskLastUpdatedDateTime
                              ? new Date(
                                  u.riskLastUpdatedDateTime,
                                ).toLocaleString()
                              : '—'}
                          </td>
                          {isAdmin && (
                            <td className="px-4 py-3 text-right space-x-1.5 whitespace-nowrap">
                              <button
                                type="button"
                                disabled={riskyActionMutation.isPending}
                                onClick={() =>
                                  riskyActionMutation.mutate({
                                    userId: u.id,
                                    userPrincipalName:
                                      u.userPrincipalName || u.id,
                                    action: 'confirm_compromised',
                                  })
                                }
                                className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-700 text-white font-medium cursor-pointer"
                              >
                                Confirm Compromised
                              </button>
                              <button
                                type="button"
                                disabled={riskyActionMutation.isPending}
                                onClick={() =>
                                  riskyActionMutation.mutate({
                                    userId: u.id,
                                    userPrincipalName:
                                      u.userPrincipalName || u.id,
                                    action: 'dismiss',
                                  })
                                }
                                className="px-2.5 py-1 rounded border border-slate-300 bg-white hover:bg-slate-50 cursor-pointer"
                              >
                                Dismiss
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function NoticeBanner({ error }: { error: FriendlyGraphError }) {
  return (
    <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-950 space-y-1.5">
      <div className="font-semibold flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-600 shrink-0" />
        <span>{error.title}</span>
      </div>
      <p>{error.message}</p>
      {error.licenseHint && (
        <p className="text-amber-800">
          <strong>License note:</strong> {error.licenseHint}
        </p>
      )}
      {error.requiredPermissions && error.requiredPermissions.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-0.5">
          {error.requiredPermissions.map((p) => (
            <code
              key={p}
              className="px-1.5 py-0.5 rounded bg-amber-100 border border-amber-300 font-mono text-[11px]"
            >
              {p}
            </code>
          ))}
        </div>
      )}
    </div>
  )
}
