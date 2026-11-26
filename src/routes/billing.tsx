import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  CreditCard,
  KeyRound,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'
import { useState } from 'react'
import {
  applyLicenseKeyFn,
  getBillingStatusFn,
} from '~/server/functions/billing'

export const Route = createFileRoute('/billing')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Plan & Licensing — Pocket365' }],
  }),
  component: BillingPage,
})

function BillingPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()

  const [licenseKey, setLicenseKey] = useState('')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  const query = useQuery({
    queryKey: ['billing-status'],
    queryFn: () => getBillingStatusFn(),
  })

  const applyMutation = useMutation({
    mutationFn: () => applyLicenseKeyFn({ data: { licenseKey } }),
    onSuccess: (res) => {
      setLicenseKey('')
      setBanner({
        type: 'success',
        text: `Activated ${res.plan.tier.toUpperCase()} license for ${res.plan.licensee}.`,
      })
      queryClient.invalidateQueries({ queryKey: ['billing-status'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Failed to verify Ed25519 license key.',
      })
    },
  })

  const plan = query.data?.plan

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Plan, Entitlements & Licensing
          </h1>
          <p className="text-sm text-slate-600">
            Manage commercial tier entitlements via offline Ed25519-signed
            license keys or Stripe subscription webhooks.
          </p>
        </div>
        <button
          type="button"
          onClick={() => query.refetch()}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-indigo-600 text-white hover:bg-indigo-700 cursor-pointer"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${query.isFetching ? 'animate-spin' : ''}`}
          />
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
            className="text-xs underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {plan && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
            <div className="text-[11px] uppercase font-medium text-slate-500">
              Active Tier
            </div>
            <div className="mt-1 text-xl font-bold text-indigo-700 uppercase">
              {plan.tier}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Source: {plan.source} • Mode: {plan.enforcement}
            </div>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
            <div className="text-[11px] uppercase font-medium text-slate-500">
              Licensee
            </div>
            <div className="mt-1 text-lg font-bold text-slate-900 truncate">
              {plan.licensee}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {plan.expiresAt
                ? `Expires ${new Date(plan.expiresAt).toLocaleDateString()}`
                : 'No expiration'}
            </div>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
            <div className="text-[11px] uppercase font-medium text-slate-500">
              Managed Quota
            </div>
            <div className="mt-1 text-xl font-bold text-slate-900">
              {plan.maxTenants} tenant(s)
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              Up to {plan.maxUsers.toLocaleString()} users
            </div>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs">
            <div className="text-[11px] uppercase font-medium text-slate-500">
              Stripe Webhook
            </div>
            <div className="mt-1 text-lg font-bold text-slate-900">
              {query.data?.stripeConfigured ? 'Connected' : 'Ready (Unset)'}
            </div>
            <div className="text-xs font-mono text-slate-500 mt-0.5">
              POST /api/billing/webhook
            </div>
          </div>
        </div>
      )}

      {/* Tier Comparison Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {(query.data?.catalog ?? []).map((tierDef) => {
          const isCurrent = plan?.tier === tierDef.tier
          return (
            <div
              key={tierDef.tier}
              className={`bg-white rounded-xl border p-5 shadow-xs space-y-4 ${
                isCurrent
                  ? 'border-indigo-500 ring-1 ring-indigo-500'
                  : 'border-slate-200'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h2 className="text-base font-bold text-slate-900">
                    {tierDef.name}
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {tierDef.tagline}
                  </p>
                </div>
                {isCurrent && (
                  <span className="px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200 text-[11px] font-semibold">
                    Current
                  </span>
                )}
              </div>

              <div className="text-xs text-slate-600 border-y border-slate-100 py-2.5 grid grid-cols-2 gap-2">
                <div>
                  Tenants: <strong>{tierDef.maxTenants}</strong>
                </div>
                <div>
                  Users: <strong>{tierDef.maxUsers.toLocaleString()}</strong>
                </div>
                <div>
                  Webhooks: <strong>{tierDef.maxWebhooks}</strong>
                </div>
                <div>
                  Retention: <strong>{tierDef.auditRetentionDays}d</strong>
                </div>
              </div>

              <ul className="space-y-1.5 text-xs text-slate-700">
                {tierDef.features.map((f) => (
                  <li key={f} className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
                    <code className="font-mono text-[11px]">{f}</code>
                  </li>
                ))}
              </ul>
            </div>
          )
        })}
      </div>

      {/* Offline License Key Activation */}
      {isAdmin && (
        <section className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <KeyRound className="h-4 w-4 text-indigo-600" />
            Apply Offline Ed25519-Signed License Key
          </div>
          <p className="text-xs text-slate-600">
            Self-hosted Docker/Portainer deployments can activate Pro or
            Enterprise offline without external telemetry by configuring{' '}
            <code className="font-mono">LICENSE_PUBLIC_KEY</code> and applying a
            signed JWT license key below.
          </p>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault()
              applyMutation.mutate()
            }}
          >
            <textarea
              rows={3}
              required
              value={licenseKey}
              onChange={(e) => setLicenseKey(e.target.value)}
              placeholder="Paste Ed25519-signed license JWT..."
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-lg"
            />
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs text-slate-500 inline-flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-indigo-600" />
                Public verification key:{' '}
                {query.data?.licensePublicKeyConfigured
                  ? 'Configured'
                  : 'Not set (set LICENSE_PUBLIC_KEY env var)'}
              </span>
              <button
                type="submit"
                disabled={applyMutation.isPending}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
              >
                <CreditCard className="h-3.5 w-3.5" />
                {applyMutation.isPending ? 'Verifying...' : 'Activate License'}
              </button>
            </div>
          </form>
        </section>
      )}
    </div>
  )
}
