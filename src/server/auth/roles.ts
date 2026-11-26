import { getConfig } from '~/server/config'
import type { UserRole } from '~/server/db/schema'

export interface RoleResolutionInput {
  oid: string
  preferredUsername?: string
  upn?: string
  email?: string
  groups?: string[]
}

export type AppCapability =
  | 'read'
  | 'helpdesk.actions' // password reset, TAP, MFA delete, revoke sessions, OOF, device sync
  | 'audit.sweep' // run BEC sweep, CIS scan, alert checks
  | 'admin.mutations' // CIS 1-click fixes, offboarding, onboarding, licenses, groups, roles, BitLocker, webhooks
  | 'owner.manage' // manage billing/license, revoke other users' sessions, manage tenants

const ROLE_CAPABILITIES: Record<UserRole, Set<AppCapability>> = {
  owner: new Set([
    'read',
    'helpdesk.actions',
    'audit.sweep',
    'admin.mutations',
    'owner.manage',
  ]),
  admin: new Set([
    'read',
    'helpdesk.actions',
    'audit.sweep',
    'admin.mutations',
    'owner.manage',
  ]),
  helpdesk: new Set(['read', 'helpdesk.actions']),
  security_auditor: new Set(['read', 'audit.sweep']),
  viewer: new Set(['read']),
}

export function hasCapability(
  role: UserRole,
  capability: AppCapability,
): boolean {
  return ROLE_CAPABILITIES[role]?.has(capability) ?? false
}

export function isAdminRole(role: UserRole): boolean {
  return role === 'owner' || role === 'admin'
}

export function roleDisplayLabel(role: UserRole): string {
  switch (role) {
    case 'owner':
      return 'owner'
    case 'admin':
      return 'full-admin'
    case 'helpdesk':
      return 'helpdesk'
    case 'security_auditor':
      return 'auditor'
    case 'viewer':
    default:
      return 'read-only'
  }
}

/**
 * Maps an authenticated Entra ID user to the highest matching role:
 * owner > admin > helpdesk > security_auditor > viewer.
 * Returns null if the user does not match any explicitly permitted principal or group.
 */
export function resolveUserRole(input: RoleResolutionInput): UserRole | null {
  const cfg = getConfig()
  const candidates = new Set<string>()

  const addCandidate = (value?: string) => {
    const normalized = value?.trim().toLowerCase()
    if (normalized) candidates.add(normalized)
  }

  addCandidate(input.oid)
  addCandidate(input.preferredUsername)
  addCandidate(input.upn)
  addCandidate(input.email)

  if (Array.isArray(input.groups)) {
    for (const groupId of input.groups) {
      addCandidate(groupId)
    }
  }

  const orderedRules: Array<[string[], UserRole]> = [
    [cfg.ownerEntries, 'owner'],
    [cfg.adminEntries, 'admin'],
    [cfg.helpdeskEntries, 'helpdesk'],
    [cfg.auditorEntries, 'security_auditor'],
    [cfg.viewerEntries, 'viewer'],
  ]

  for (const [entries, role] of orderedRules) {
    for (const allowed of entries) {
      if (candidates.has(allowed)) {
        return role
      }
    }
  }

  return null
}
