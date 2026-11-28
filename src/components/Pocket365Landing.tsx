import { Link } from '@tanstack/react-router'
import {
  Activity,
  ArrowRight,
  Building2,
  CheckCircle2,
  Cloud,
  ExternalLink,
  FileCheck2,
  KeyRound,
  Lock,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
  Wrench,
  Zap,
} from 'lucide-react'
import type { DeploymentMode } from '~/server/config'

export interface Pocket365LandingProps {
  deploymentMode: DeploymentMode
  needsSetup: boolean
}

const CAPABILITIES = [
  {
    icon: ShieldCheck,
    title: '24 CIS M365 Benchmarks + 1-Click Fixes',
    description:
      'Continuously score your tenant against CIS Microsoft 365 Foundations with 16 automated 1-click remediations and archived Cloudflare R2 compliance snapshots.',
  },
  {
    icon: Activity,
    title: 'AADSTS Sign-In Diagnostics',
    description:
      'Troubleshoot failed Entra ID sign-ins in seconds with built-in AADSTS error diagnosis, Conditional Access policy traces, and device compliance context.',
  },
  {
    icon: KeyRound,
    title: 'MFA & Privileged Role Governance',
    description:
      'Audit MFA registration coverage, monitor Global Admin sprawl, issue Temporary Access Passes safely, and catch stale or risky accounts before attackers do.',
  },
  {
    icon: Building2,
    title: 'Multi-Tenant MSP Command Center',
    description:
      'Onboard customer M365 tenants via 1-click Microsoft Admin Consent with zero per-customer secrets stored in the database and strict per-tenant isolation.',
  },
  {
    icon: Lock,
    title: '5-Tier RBAC & Immutable Audit Logs',
    description:
      'Enforce Owner, Admin, Helpdesk, Auditor, and Viewer roles server-side with PKCE OIDC authentication, active session revocation, and full D1 audit trails.',
  },
  {
    icon: Zap,
    title: '100% Cloudflare Edge Runtime',
    description:
      'Zero cold starts and zero VMs to patch. Runs natively on Cloudflare Workers, D1, KV, R2, and Cron Triggers with DNS-over-HTTPS email security checks.',
  },
]

const TIERS = [
  {
    name: 'Community Self-Hosted',
    price: '$0',
    period: 'forever',
    badge: 'Single-Tenant',
    description:
      'Deploy Pocket365 to your own Cloudflare account in minutes using the built-in browser setup wizard.',
    highlights: [
      'Full Cloudflare Free-tier compatible',
      'Entra ID OIDC + 5-tier RBAC',
      'User, Group, Mailbox & Sign-in tools',
      '1-Click PowerShell Entra App bootstrap',
    ],
    ctaLabel: 'Deploy to Cloudflare',
    ctaHref:
      'https://deploy.workers.cloudflare.com/?url=https://github.com/bangsmackpow/pocket365',
    external: true,
    featured: false,
  },
  {
    name: 'Pro Single-Tenant',
    price: '$49',
    period: '/month',
    badge: 'Most Popular',
    description:
      'Unlock automated CIS remediation, R2 compliance snapshots, scheduled drift alerts, and priority support.',
    highlights: [
      'Everything in Community Self-Hosted',
      'All 24 CIS Benchmarks + 16 1-click fixes',
      'Automated Teams/Slack/Discord drift alerts',
      'Offline Ed25519-signed license key',
    ],
    ctaLabel: 'View Licensing on Built by Vets',
    ctaHref: 'https://builtbyvets.app/apps/pocket365#pricing',
    external: true,
    featured: true,
  },
  {
    name: 'Hosted MSP Cloud',
    price: '$149',
    period: '/month',
    badge: 'Multi-Tenant MSP',
    description:
      'Managed cloud console with unlimited customer tenant onboarding via zero-secret Admin Consent.',
    highlights: [
      'Zero infrastructure to maintain',
      'Multi-tenant MSP Command Center',
      'Per-technician tenant access scoping',
      'Isolated org data across D1, KV & R2',
    ],
    ctaLabel: 'Sign In to Cloud Console',
    ctaHref: '/login',
    external: false,
    featured: false,
  },
]

export function Pocket365Landing({
  deploymentMode,
  needsSetup,
}: Pocket365LandingProps) {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* Top Navigation */}
      <header className="sticky top-0 z-30 bg-white/90 backdrop-blur border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-indigo-600 flex items-center justify-center shadow-sm">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div className="flex items-center gap-2.5">
              <span className="text-lg font-bold tracking-tight text-slate-900">
                Pocket365
              </span>
              <a
                href="https://builtbyvets.app"
                target="_blank"
                rel="noreferrer"
                className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-100 text-slate-700 border border-slate-200 hover:border-indigo-300 hover:text-indigo-700 transition-colors"
              >
                <Shield className="h-3 w-3 text-amber-600" />
                Built by Vets
              </a>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
            <a href="#features" className="hover:text-slate-900 transition-colors">
              Features
            </a>
            <a href="#deployment" className="hover:text-slate-900 transition-colors">
              Deployment
            </a>
            <a href="#pricing" className="hover:text-slate-900 transition-colors">
              Pricing
            </a>
            <a
              href="https://builtbyvets.app"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 hover:text-indigo-600 transition-colors"
            >
              All Apps
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </nav>

          <div className="flex items-center gap-2.5">
            {needsSetup && (
              <Link
                to="/setup"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-200 hover:bg-amber-100 transition-colors"
              >
                <Wrench className="h-3.5 w-3.5" />
                First-Run Setup
              </Link>
            )}
            <Link
              to="/login"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-indigo-600 hover:bg-indigo-700 text-white shadow-sm transition-colors"
            >
              <Lock className="h-4 w-4" />
              Sign In
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden bg-slate-950 text-white">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_rgba(79,70,229,0.28),_transparent_55%),radial-gradient(ellipse_at_bottom_left,_rgba(15,23,42,0.9),_transparent_60%)]"
        />
        <div className="relative max-w-7xl mx-auto px-6 py-20 lg:py-28">
          <div className="max-w-3xl space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 border border-white/15 text-xs font-medium text-indigo-200">
              <Sparkles className="h-3.5 w-3.5 text-amber-400" />
              <span>
                {deploymentMode === 'saas'
                  ? 'Pocket365 Cloud SaaS — Multi-Tenant MSP & M365 Security Console'
                  : 'Pocket365 Self-Hosted — Cloudflare-Native M365 Administration'}
              </span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight leading-[1.1]">
              Microsoft 365 Security &amp; MSP Operations,{' '}
              <span className="text-indigo-400">at Cloudflare Edge Speed.</span>
            </h1>

            <p className="text-lg text-slate-300 leading-relaxed max-w-2xl">
              Audit 24 CIS M365 benchmarks, remediate drift in one click, diagnose
              AADSTS sign-in failures, and manage customer tenants with zero stored
              customer secrets. Built by US military veterans for IT teams and MSPs
              who demand speed and rigor.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <Link
                to="/login"
                className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-semibold shadow-lg shadow-indigo-950/50 transition-colors"
              >
                <Lock className="h-4 w-4" />
                Sign In with Microsoft Entra ID
                <ArrowRight className="h-4 w-4" />
              </Link>
              <a
                href="https://deploy.workers.cloudflare.com/?url=https://github.com/bangsmackpow/pocket365"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-5 py-3.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/15 text-white text-sm font-semibold transition-colors"
              >
                <Cloud className="h-4 w-4 text-amber-400" />
                Deploy Self-Hosted on Cloudflare
              </a>
            </div>

            <div className="pt-6 grid grid-cols-2 sm:grid-cols-4 gap-4 border-t border-white/10">
              {[
                { label: 'CIS Benchmarks', value: '24 Checks' },
                { label: 'Automated Fixes', value: '16 1-Click' },
                { label: 'RBAC Tiers', value: '5 Roles' },
                { label: 'Cold Starts', value: '0 ms Edge' },
              ].map((stat) => (
                <div key={stat.label}>
                  <div className="text-xl font-bold text-white">{stat.value}</div>
                  <div className="text-xs text-slate-400">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <section id="features" className="max-w-7xl mx-auto px-6 py-20 w-full">
        <div className="max-w-2xl mb-12">
          <div className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
            Capabilities
          </div>
          <h2 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
            Everything Microsoft 365 admins need — without portal sprawl
          </h2>
          <p className="mt-3 text-base text-slate-600">
            Replace slow PowerShell scripts and half a dozen Microsoft admin portals
            with one unified, audit-logged console built on Cloudflare Workers.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {CAPABILITIES.map((cap) => {
            const Icon = cap.icon
            return (
              <div
                key={cap.title}
                className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm hover:border-indigo-200 hover:shadow-md transition-all"
              >
                <div className="h-10 w-10 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center mb-4">
                  <Icon className="h-5 w-5 text-indigo-600" />
                </div>
                <h3 className="text-base font-semibold text-slate-900">
                  {cap.title}
                </h3>
                <p className="mt-2 text-sm text-slate-600 leading-relaxed">
                  {cap.description}
                </p>
              </div>
            )
          })}
        </div>
      </section>

      {/* Deployment Models */}
      <section
        id="deployment"
        className="bg-white border-y border-slate-200 py-20 w-full"
      >
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-2xl mb-12">
            <div className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
              Deploy Your Way
            </div>
            <h2 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
              Managed Cloud or 100% Self-Hosted on Your Cloudflare Account
            </h2>
            <p className="mt-3 text-base text-slate-600">
              Keep complete data sovereignty on your own Cloudflare Workers, D1, KV,
              and R2 — or sign in instantly to our managed multi-tenant cloud.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="rounded-2xl bg-slate-50 border border-slate-200 p-8 space-y-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-slate-200 text-xs font-semibold text-slate-700">
                <Server className="h-3.5 w-3.5 text-indigo-600" />
                Self-Hosted (`DEPLOYMENT_MODE=self_hosted`)
              </div>
              <h3 className="text-xl font-bold text-slate-900">
                Your Cloudflare Account, Your Keys
              </h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Deploy directly to your own Cloudflare account with a 1-click setup
                wizard and PowerShell Entra App bootstrap script. All credentials
                are encrypted at rest with key-versioned AES-256-GCM.
              </p>
              <ul className="space-y-2 text-sm text-slate-700 pt-2">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
                  Runs on Cloudflare Free or Paid Workers plan
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
                  Zero third-party data egress
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
                  Upgrade anytime with an offline Ed25519 license key
                </li>
              </ul>
            </div>

            <div className="rounded-2xl bg-slate-900 text-white border border-slate-800 p-8 space-y-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 border border-white/15 text-xs font-semibold text-indigo-200">
                <Cloud className="h-3.5 w-3.5 text-amber-400" />
                Managed SaaS (`DEPLOYMENT_MODE=saas`)
              </div>
              <h3 className="text-xl font-bold text-white">
                Instant Multi-Tenant MSP Cloud
              </h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                Sign in with your Microsoft Entra ID organizational account and
                Pocket365 auto-provisions an isolated workspace for your team.
                Onboard customer tenants in one click via Microsoft Admin Consent.
              </p>
              <ul className="space-y-2 text-sm text-slate-200 pt-2">
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-indigo-400 shrink-0" />
                  Strict organization isolation across D1, KV &amp; R2
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-indigo-400 shrink-0" />
                  Zero per-customer client secrets stored
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-indigo-400 shrink-0" />
                  Self-service Stripe billing &amp; instant upgrades
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing & Licensing */}
      <section id="pricing" className="max-w-7xl mx-auto px-6 py-20 w-full">
        <div className="text-center max-w-2xl mx-auto mb-12">
          <div className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
            Transparent Licensing
          </div>
          <h2 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
            Start Free, Scale to Multi-Tenant MSP
          </h2>
          <p className="mt-3 text-base text-slate-600">
            Purchase and manage licenses individually through the Built by Vets
            portal or self-host the Community edition free forever.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {TIERS.map((tier) => (
            <div
              key={tier.name}
              className={`rounded-2xl p-7 flex flex-col justify-between border ${
                tier.featured
                  ? 'bg-slate-900 text-white border-indigo-500 shadow-xl ring-1 ring-indigo-500/40'
                  : 'bg-white text-slate-900 border-slate-200 shadow-sm'
              }`}
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-lg font-bold">{tier.name}</h3>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                      tier.featured
                        ? 'bg-indigo-600 text-white'
                        : 'bg-slate-100 text-slate-700'
                    }`}
                  >
                    {tier.badge}
                  </span>
                </div>

                <div className="flex items-baseline gap-1">
                  <span className="text-4xl font-bold tracking-tight">
                    {tier.price}
                  </span>
                  <span
                    className={`text-sm ${
                      tier.featured ? 'text-slate-400' : 'text-slate-500'
                    }`}
                  >
                    {tier.period}
                  </span>
                </div>

                <p
                  className={`text-sm leading-relaxed ${
                    tier.featured ? 'text-slate-300' : 'text-slate-600'
                  }`}
                >
                  {tier.description}
                </p>

                <ul className="space-y-2.5 pt-2">
                  {tier.highlights.map((item) => (
                    <li key={item} className="flex items-start gap-2 text-sm">
                      <CheckCircle2
                        className={`h-4 w-4 shrink-0 mt-0.5 ${
                          tier.featured ? 'text-indigo-400' : 'text-emerald-600'
                        }`}
                      />
                      <span
                        className={
                          tier.featured ? 'text-slate-200' : 'text-slate-700'
                        }
                      >
                        {item}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-8">
                {tier.external ? (
                  <a
                    href={tier.ctaHref}
                    target="_blank"
                    rel="noreferrer"
                    className={`w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm font-semibold transition-colors ${
                      tier.featured
                        ? 'bg-indigo-600 hover:bg-indigo-500 text-white'
                        : 'bg-slate-900 hover:bg-slate-800 text-white'
                    }`}
                  >
                    {tier.ctaLabel}
                    <ExternalLink className="h-4 w-4" />
                  </a>
                ) : (
                  <Link
                    to="/login"
                    className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-sm font-semibold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors"
                  >
                    {tier.ctaLabel}
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto bg-white border-t border-slate-200">
        <div className="max-w-7xl mx-auto px-6 py-10 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-600">
          <div className="flex items-center gap-2.5">
            <FileCheck2 className="h-4 w-4 text-indigo-600" />
            <span className="font-semibold text-slate-900">Pocket365</span>
            <span className="text-slate-400">•</span>
            <span>
              Part of the{' '}
              <a
                href="https://builtbyvets.app"
                target="_blank"
                rel="noreferrer"
                className="font-semibold text-indigo-600 hover:text-indigo-700"
              >
                Built by Vets
              </a>{' '}
              software suite
            </span>
          </div>
          <div className="flex items-center gap-5 text-xs">
            <a
              href="https://builtbyvets.app/apps/pocket365"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-900"
            >
              Product Info
            </a>
            <Link to="/login" className="hover:text-slate-900">
              Sign In
            </Link>
            <a
              href="https://builtbyvets.app"
              target="_blank"
              rel="noreferrer"
              className="hover:text-slate-900"
            >
              builtbyvets.app
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
