import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  RefreshCw,
  Save,
  Settings,
  ShieldAlert,
  Wrench,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  getDashboardDataFn,
  updateRuntimeSettingsFn,
} from '~/server/functions/dashboard'
import { getGraphPermissionsStatusFn } from '~/server/functions/signins'

export const Route = createFileRoute('/admin')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'System & API Administration — Pocket365' }],
  }),
  component: AdminPage,
})

function AdminPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => getDashboardDataFn(),
  })

  const permsQuery = useQuery({
    queryKey: ['graph-permissions'],
    queryFn: () => getGraphPermissionsStatusFn(),
  })

  const [defaultPageSize, setDefaultPageSize] = useState(25)
  const [auditRetentionDays, setAuditRetentionDays] = useState(90)
  const [organizationBanner, setOrganizationBanner] = useState('')
  const [bulkJobDelayMs, setBulkJobDelayMs] = useState(150)
  const [autoRemediateDrift, setAutoRemediateDrift] = useState(false)
  const [saveMessage, setSaveMessage] = useState<string | null>(null)

  useEffect(() => {
    if (data?.settings) {
      setDefaultPageSize(data.settings.defaultPageSize)
      setAuditRetentionDays(data.settings.auditRetentionDays)
      setOrganizationBanner(data.settings.organizationBanner)
      setBulkJobDelayMs(data.settings.bulkJobDelayMs)
      setAutoRemediateDrift(data.settings.autoRemediateDrift ?? false)
    }
  }, [data?.settings])

  const saveSettingsMutation = useMutation({
    mutationFn: () =>
      updateRuntimeSettingsFn({
        data: {
          defaultPageSize,
          auditRetentionDays,
          organizationBanner,
          bulkJobDelayMs,
          autoRemediateDrift,
        },
      }),
    onSuccess: () => {
      setSaveMessage('Runtime settings saved and recorded in audit log.')
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (err) => {
      setSaveMessage(
        err instanceof Error ? err.message : 'Failed to save settings.',
      )
    },
  })

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-64 bg-slate-200 animate-pulse rounded-lg" />
        <div className="h-48 bg-white border border-slate-200 rounded-xl animate-pulse" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2.5">
            <Wrench className="h-6 w-6 text-indigo-600" />
            System & API Administration
          </h1>
          <p className="text-sm text-slate-600">
            Cloudflare platform health, Microsoft Graph application permissions,
            and tenant runtime settings.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['dashboard'] })
            queryClient.invalidateQueries({ queryKey: ['graph-permissions'] })
          }}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh Diagnostics
        </button>
      </div>

      {/* Cloudflare Edge Platform Health */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Cpu className="h-4 w-4 text-indigo-600" />
            Cloudflare Workers Edge Architecture Status
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            Mode: {data?.deploymentMode ?? 'self_hosted'}
          </span>
        </div>
        <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 flex items-start gap-3">
            <Database className="h-5 w-5 text-indigo-600 mt-0.5" />
            <div className="min-w-0">
              <div className="text-xs text-slate-500 font-medium">Cloudflare D1</div>
              <div className="text-sm font-semibold text-slate-900 mt-0.5">SQLite at Edge</div>
              <div className="text-[11px] text-emerald-700 font-medium mt-1 flex items-center gap-1">
                <CheckCircle2 className="h-3.5 w-3.5" /> Active & Migrated
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 flex items-start gap-3">
            <Layers className="h-5 w-5 text-indigo-600 mt-0.5" />
            <div className="min-w-0">
              <div className="text-xs text-slate-500 font-medium">Cloudflare KV</div>
              <div className="text-sm font-semibold text-slate-900 mt-0.5">Rate Limit & Cache</div>
              <div className="text-[11px] text-emerald-700 font-medium mt-1 flex items-center gap-1">
                <CheckCircle2 className="h-3.5 w-3.5" /> POCKET365_KV
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 flex items-start gap-3">
            <HardDrive className="h-5 w-5 text-indigo-600 mt-0.5" />
            <div className="min-w-0">
              <div className="text-xs text-slate-500 font-medium">Cloudflare R2</div>
              <div className="text-sm font-semibold text-slate-900 mt-0.5">Audit Archives</div>
              <div className="text-[11px] text-emerald-700 font-medium mt-1 flex items-center gap-1">
                <CheckCircle2 className="h-3.5 w-3.5" /> pocket365-exports
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 flex items-start gap-3">
            <Lock className="h-5 w-5 text-indigo-600 mt-0.5" />
            <div className="min-w-0">
              <div className="text-xs text-slate-500 font-medium">Data Encryption</div>
              <div className="text-sm font-semibold text-slate-900 mt-0.5">Key-Versioned v2</div>
              <div className="text-[11px] text-emerald-700 font-medium mt-1 flex items-center gap-1">
                <CheckCircle2 className="h-3.5 w-3.5" /> AES-256-GCM Rotatable
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Microsoft Graph Permissions Readiness */}
      {permsQuery.data && (
        <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-indigo-600" />
                Microsoft Graph Application Permissions Readiness
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Evaluated against the active App-Only client credentials token in Entra ID.
              </p>
            </div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 text-slate-800">
              {permsQuery.data.requirements.filter((r) => r.granted).length} /{' '}
              {permsQuery.data.requirements.length} Granted
            </span>
          </div>

          {/* Admin Consent Alert & 1-Click Action */}
          {permsQuery.data.requirements.some((r) => !r.granted) && (
            <div className="p-4 bg-amber-50 border-b border-amber-200 text-amber-900 flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="text-xs font-semibold flex items-center gap-1.5 text-amber-900">
                  <ShieldAlert className="h-4 w-4 text-amber-600 shrink-0" />
                  Admin Consent Required in Microsoft Entra ID
                </div>
                <div className="text-xs text-amber-800">
                  {permsQuery.data.error ? (
                    <span>
                      Error: <span className="font-mono">{permsQuery.data.error}</span>
                    </span>
                  ) : (
                    'Application permissions require tenant-wide administrator consent before Microsoft Graph grants access.'
                  )}
                </div>
              </div>
              {permsQuery.data.consentUrl && (
                <a
                  href={permsQuery.data.consentUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-600 text-white hover:bg-amber-700 shadow-xs transition-colors shrink-0"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  Grant Admin Consent Now
                </a>
              )}
            </div>
          )}

          <div className="divide-y divide-slate-100 max-h-[500px] overflow-y-auto">
            {permsQuery.data.requirements.map((req) => (
              <div
                key={req.permission}
                className="px-5 py-3 flex flex-wrap items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <code className="font-mono font-semibold text-slate-900">
                      {req.permission}
                    </code>
                    <span className="text-slate-500">• {req.module}</span>
                  </div>
                  <div className="text-slate-500 mt-0.5">{req.purpose}</div>
                </div>
                <span
                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border shrink-0 ${
                    req.granted
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-amber-50 text-amber-800 border-amber-200'
                  }`}
                >
                  {req.granted ? 'Granted' : 'Missing'}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Non-Secret Runtime Settings */}
      <section className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Settings className="h-4 w-4 text-indigo-600" />
            Runtime Settings (Non-Secret)
          </h2>
          <span className="text-xs text-slate-500">
            {isAdmin ? 'Admin editable' : 'Read-only'}
          </span>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-700">
                Default Page Size
              </span>
              <input
                type="number"
                min={10}
                max={100}
                disabled={!isAdmin}
                value={defaultPageSize}
                onChange={(e) => setDefaultPageSize(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
              />
            </label>
            <label className="block space-y-1">
              <span className="text-xs font-medium text-slate-700">
                Audit Retention (Days)
              </span>
              <input
                type="number"
                min={7}
                max={3650}
                disabled={!isAdmin}
                value={auditRetentionDays}
                onChange={(e) => setAuditRetentionDays(Number(e.target.value))}
                className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
              />
            </label>
          </div>

          <label className="block space-y-1">
            <span className="text-xs font-medium text-slate-700">
              Bulk Job Throttle Delay (ms)
            </span>
            <input
              type="number"
              min={0}
              max={5000}
              disabled={!isAdmin}
              value={bulkJobDelayMs}
              onChange={(e) => setBulkJobDelayMs(Number(e.target.value))}
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
            />
          </label>

          <label className="block space-y-1">
            <span className="text-xs font-medium text-slate-700">
              Operator Notice Banner
            </span>
            <input
              type="text"
              maxLength={240}
              placeholder="Optional maintenance or tenant notice..."
              disabled={!isAdmin}
              value={organizationBanner}
              onChange={(e) => setOrganizationBanner(e.target.value)}
              className="w-full px-3 py-2 text-sm border border-slate-300 rounded-lg disabled:bg-slate-50 disabled:text-slate-500"
            />
          </label>

          <div className="pt-3 border-t border-slate-100">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                disabled={!isAdmin}
                checked={autoRemediateDrift}
                onChange={(e) => setAutoRemediateDrift(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
              />
              <div className="space-y-0.5">
                <span className="text-xs font-semibold text-slate-900 block">
                  Automated Standards Drift Remediation (CIPP Standards)
                </span>
                <span className="text-xs text-slate-500 block">
                  When enabled, scheduled sweeps will automatically re-harden drifted tenant controls (such as Security Defaults, MFA context, and sharing restrictions) and record an immutable audit trail.
                </span>
              </div>
            </label>
          </div>

          {saveMessage && (
            <div className="flex items-center gap-2 text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-2 rounded-lg">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{saveMessage}</span>
            </div>
          )}

          {isAdmin && (
            <button
              type="button"
              disabled={saveSettingsMutation.isPending}
              onClick={() => {
                setSaveMessage(null)
                saveSettingsMutation.mutate()
              }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
            >
              <Save className="h-4 w-4" />
              {saveSettingsMutation.isPending ? 'Saving...' : 'Save Settings'}
            </button>
          )}
        </div>
      </section>
    </div>
  )
}
