import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useRouter, useRouterState } from '@tanstack/react-router'
import {
  Activity,
  AppWindow,
  Bell,
  Building2,
  ClipboardCheck,
  CreditCard,
  Crown,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Mail,
  Radar,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserMinus,
  UserPlus,
  Users,
  UsersRound,
} from 'lucide-react'
import type { ReactNode } from 'react'
import type { UserRole } from '~/server/db/schema'
import { switchActiveTenantFn } from '~/server/functions/tenants'

export interface ClientSessionUser {
  oid: string
  upn: string
  displayName: string
  role: UserRole
  expiresAt: number
}

export interface TenantSwitcherOption {
  id: string
  displayName: string
  primaryDomain: string
  isPrimary: boolean
}

interface AppShellProps {
  user: ClientSessionUser
  deploymentMode?: 'self_hosted' | 'saas'
  tenantIdHint: string | null
  activeTenantId?: string | null
  accessibleTenants?: TenantSwitcherOption[]
  children: ReactNode
}

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/tenants', label: 'Tenants (MSP)', icon: Building2 },
  { to: '/signins', label: 'Sign-in Logs', icon: KeyRound },
  { to: '/mfa', label: 'MFA Coverage', icon: ShieldAlert },
  { to: '/cis', label: 'CIS Benchmarks', icon: ClipboardCheck },
  { to: '/roles', label: 'Privileged Roles', icon: Crown },
  { to: '/users', label: 'Users', icon: Users },
  { to: '/onboarding', label: 'Onboarding', icon: UserPlus },
  { to: '/groups', label: 'Groups', icon: UsersRound },
  { to: '/mailboxes', label: 'Mailboxes', icon: Mail },
  { to: '/apps', label: 'Apps & OAuth', icon: AppWindow },
  { to: '/cleanup', label: 'Stale & Guests', icon: UserMinus },
  { to: '/posture', label: 'Posture & Devices', icon: Radar },
  { to: '/alerts', label: 'Alerts', icon: Bell },
  { to: '/security', label: 'Security & Sessions', icon: Lock },
  { to: '/billing', label: 'Plan & Licensing', icon: CreditCard },
  { to: '/audit', label: 'Audit & Jobs', icon: Activity },
] as const

function formatRoleLabel(role: UserRole): string {
  if (role === 'owner') return 'owner'
  if (role === 'admin') return 'full-admin'
  if (role === 'helpdesk') return 'helpdesk'
  if (role === 'security_auditor') return 'auditor'
  return 'read-only'
}

export function AppShell({
  user,
  deploymentMode = 'self_hosted',
  tenantIdHint,
  activeTenantId,
  accessibleTenants = [],
  children,
}: AppShellProps) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const router = useRouter()
  const queryClient = useQueryClient()
  const isAdmin = user.role === 'admin' || user.role === 'owner'
  const isSaas = deploymentMode === 'saas'
  const visibleNavItems = isSaas
    ? NAV_ITEMS
    : NAV_ITEMS.filter((item) => item.to !== '/tenants')

  const switchTenantMutation = useMutation({
    mutationFn: (managedTenantId: string) =>
      switchActiveTenantFn({ data: { managedTenantId } }),
    onSuccess: async () => {
      await queryClient.invalidateQueries()
      await router.invalidate()
    },
  })

  return (
    <div className="min-h-screen flex bg-slate-50 text-slate-900">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 bg-slate-950 text-slate-100 flex flex-col border-r border-slate-800">
        <div className="px-5 py-5 border-b border-slate-800 space-y-3">
          <Link to="/" className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-indigo-600 flex items-center justify-center shadow-sm">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-base font-semibold tracking-tight text-white">
                Pocket365
              </div>
              <div className="text-xs text-slate-400">
                {isSaas ? 'Cloud MSP Console' : 'Self-Hosted M365 Console'}
              </div>
            </div>
          </Link>

          {/* Global Multi-Tenant Switcher (SaaS mode) */}
          {isSaas && accessibleTenants.length > 0 && (
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1">
                <Building2 className="h-3 w-3" />
                Active Tenant
              </label>
              <select
                value={activeTenantId ?? accessibleTenants[0]?.id ?? ''}
                disabled={switchTenantMutation.isPending}
                onChange={(e) => switchTenantMutation.mutate(e.target.value)}
                className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              >
                {accessibleTenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.displayName}
                    {t.primaryDomain ? ` (${t.primaryDomain})` : ''}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {visibleNavItems.map(({ to, label, icon: Icon }) => {
            const active =
              to === '/' ? pathname === '/' : pathname.startsWith(to)
            return (
              <Link
                key={to}
                to={to}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{label}</span>
              </Link>
            )
          })}
        </nav>

        <div className="p-4 border-t border-slate-800 space-y-3">
          {tenantIdHint && (
            <div className="text-[11px] text-slate-400 font-mono truncate">
              Tenant: {tenantIdHint}
            </div>
          )}
          <div className="rounded-lg bg-slate-900 border border-slate-800 p-3 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-medium text-white truncate">
                {user.displayName}
              </span>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold ${
                  isAdmin
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                }`}
              >
                <Shield className="h-3 w-3" />
                {formatRoleLabel(user.role)}
              </span>
            </div>
            <div className="text-xs text-slate-400 truncate" title={user.upn}>
              {user.upn}
            </div>
            <form method="post" action="/api/auth/logout">
              <button
                type="submit"
                className="w-full mt-1 inline-flex items-center justify-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign out
              </button>
            </form>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {!isAdmin && (
          <div className="bg-sky-50 border-b border-sky-200 px-6 py-2 text-xs text-sky-900 flex items-center justify-between">
            <span>
              <strong>Read-Only Session:</strong> You are signed in with the{' '}
              <code className="font-mono">viewer</code> role. Mutating actions
              are disabled and strictly enforced server-side.
            </span>
          </div>
        )}
        <main className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  )
}
