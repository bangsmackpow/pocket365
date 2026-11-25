import { getConfig } from '~/server/config'
import type { UserRole } from '~/server/db/schema'

export interface RoleResolutionInput {
  oid: string
  preferredUsername?: string
  upn?: string
  email?: string
  groups?: string[]
}

/**
 * Maps an authenticated Entra ID user to either 'admin' or 'viewer' based on
 * ADMIN_OIDS_OR_GROUPS and VIEWER_OIDS_OR_GROUPS.
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

  for (const allowedAdmin of cfg.adminEntries) {
    if (candidates.has(allowedAdmin)) {
      return 'admin'
    }
  }

  for (const allowedViewer of cfg.viewerEntries) {
    if (candidates.has(allowedViewer)) {
      return 'viewer'
    }
  }

  return null
}
