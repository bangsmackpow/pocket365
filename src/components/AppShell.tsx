import { Link, useRouterState } from '@tanstack/react-router'
import {
  Activity,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Shield,
  ShieldCheck,
  Users,
  UsersRound,
} from 'lucide-react'
import type { ReactNode } from 'react'
import type { UserRole } from '~/server/db/schema'

export interface ClientSessionUser {
  oid: string
  upn: string
  displayName: string
  role: UserRole
  expiresAt: number
}

interface AppShellProps {
  user: ClientSessionUser
  tenantIdHint: string | null
  children: ReactNode
}

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/signins', label: 'Sign-in Logs', icon: KeyRound },
  { to: '/users', label: 'Users', icon: Users },
  { to: '/groups', label: 'Groups', icon: UsersRound },
  { to: '/audit', label: 'Audit & Jobs', icon: Activity },
] as const

export function AppShell({ user, tenantIdHint, children }: AppShellProps) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const isAdmin = user.role === 'admin'

  return (
    <div className="min-h-screen flex bg-slate-50 text-slate-900">
      {/* Sidebar */}
      <aside className="w-64 shrink-0 bg-slate-950 text-slate-100 flex flex-col border-r border-slate-800">
        <div className="px-5 py-5 border-b border-slate-800">
          <Link to="/" className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-indigo-600 flex items-center justify-center shadow-sm">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-base font-semibold tracking-tight text-white">
                Pocket365
              </div>
              <div className="text-xs text-slate-400">
                Single-Tenant M365 Admin
              </div>
            </div>
          </Link>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => {
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
                {isAdmin ? 'full-admin' : 'read-only'}
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
