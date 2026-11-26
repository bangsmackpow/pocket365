import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  CreditCard,
  ExternalLink,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import { useState } from 'react'
import { z } from 'zod'
import {
  applyLicenseKeyFn,
  getBillingStatusFn,
  openStripePortalFn,
  startSaasCheckoutFn,
} from '~/server/functions/billing'

const billingSearchSchema = z.object({
  checkout: z.string().optional(),
  welcome: z.string().optional(),
})

export const Route = createFileRoute('/billing')({
  validateSearch: (search) => billingSearchSchema.parse(search),
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
  const search = Route.useSearch()
  const isOwnerOrAdmin =
    auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()

  const [licenseKey, setLicenseKey] = useState('')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(
    search.checkout === 'success'
      ? {
          type: 'success',
          text: 'Subscription checkout completed! Your Pocket365 Cloud SaaS entitlements will activate automatically within seconds.',
        }
      : search.checkout === 'canceled'
        ? {
            type: 'error',
            text: 'Stripe checkout was canceled. You can restart your subscription any time below.',
          }
        : search.welcome === '1'
          ? {
              type: 'success',
              text: 'Welcome to Pocket365 Cloud! Your isolated organization is ready — subscribe below to unlock all features and unlimited multi-tenant MSP management.',
            }
          : null,
  )

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
      void queryClient.invalidateQueries({ queryKey: ['billing-status'] })
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

  const checkoutMutation = useMutation({
    mutationFn: () => startSaasCheckoutFn(),
    onSuccess: (res) => {
      window.location.href = res.url
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Unable to start Stripe Checkout.',
      })
    },
  })

  const portalMutation = useMutation({
    mutationFn: () => openStripePortalFn(),
    onSuccess: (res) => {
      window.location.href = res.url
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text:
          err instanceof Error
            ? err.message
            : 'Unable to open Stripe Billing Portal.',
      })
    },
  })

  const plan = query.data?.plan
  const isSaas = query.data?.deploymentMode === 'saas'
  const org = query.data?.organization

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Plan, Entitlements & Licensing
          </h1>
          <p className="text-sm text-slate-600">
            {isSaas
              ? 'Manage your Pocket365 Cloud SaaS subscription and unlimited multi-tenant MSP access via Stripe.'
              : 'Self-Hosted Cloudflare Workers deployment — activate Pro single-tenant features via offline Ed25519 license key.'}
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

      {/* SaaS Subscription Checkout / Billing Portal Callout */}
      {isSaas && isOwnerOrAdmin && (
        <section className="bg-slate-900 text-white rounded-2xl border border-slate-800 p-6 flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-300 uppercase tracking-wider">
              <Sparkles className="h-3.5 w-3.5" />
              Pocket365 Cloud SaaS — Single Monthly Plan
            </div>
            <h2 className="text-lg font-bold">
              {org?.name || 'Your Organization'}
            </h2>
            <p className="text-xs text-slate-300">
              Includes all CIS 1-click fixes, BEC Sweeps, Alerts, Onboarding,
              BitLocker, and unlimited zero-secret multi-tenant MSP onboarding
              via Microsoft Admin Consent.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            {org?.hasStripeCustomer && (
              <button
                type="button"
                disabled={portalMutation.isPending}
                onClick={() => portalMutation.mutate()}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-semibold cursor-pointer"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                {portalMutation.isPending
                  ? 'Opening Portal...'
                  : 'Manage Billing & Invoices'}
              </button>
            )}
            {plan?.tier !== 'enterprise' && (
              <button
                type="button"
                disabled={
                  checkoutMutation.isPending ||
                  !query.data?.stripeCheckoutConfigured
                }
                onClick={() => checkoutMutation.mutate()}
                className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
              >
                <CreditCard className="h-4 w-4" />
                {checkoutMutation.isPending
                  ? 'Redirecting to Stripe...'
                  : query.data?.stripeCheckoutConfigured
                    ? 'Subscribe with Stripe Checkout'
                    : 'Configure STRIPE_SECRET_KEY & STRIPE_PRICE_SAAS'}
              </button>
            )}
          </div>
        </section>
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
              Mode: {plan.deploymentMode} • Enforcement: {plan.enforcement}
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
              Stripe Integration
            </div>
            <div className="mt-1 text-lg font-bold text-slate-900">
              {query.data?.stripeCheckoutConfigured
                ? 'Checkout + Webhook'
                : query.data?.stripeConfigured
                  ? 'Webhook Ready'
                  : 'Unconfigured'}
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

      {/* Offline License Key Activation (Self-Hosted Cloudflare Workers) */}
      {isOwnerOrAdmin && !isSaas && (
        <section className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <KeyRound className="h-4 w-4 text-indigo-600" />
            Apply Offline Ed25519-Signed Pro License Key
          </div>
          <p className="text-xs text-slate-600">
            Self-hosted Cloudflare Workers deployments can unlock all
            single-tenant Pro features offline without external telemetry by
            setting the <code className="font-mono">LICENSE_PUBLIC_KEY</code>{' '}
            Worker secret and pasting your signed JWT license key below.
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
                  : 'Not set (set LICENSE_PUBLIC_KEY secret)'}
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
