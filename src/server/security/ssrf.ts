import dns from 'node:dns/promises'
import net from 'node:net'
import { getConfig } from '~/server/config'

export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.trim().toLowerCase()

  // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.slice(7)
    if (net.isIPv4(v4Part)) {
      return isPrivateOrReservedIp(v4Part)
    }
  }

  if (net.isIPv4(normalized)) {
    const octets = normalized.split('.').map((n) => Number.parseInt(n, 10))
    const a = octets[0] ?? 0
    const b = octets[1] ?? 0

    if (a === 0) return true // 0.0.0.0/8
    if (a === 10) return true // 10.0.0.0/8 RFC1918
    if (a === 127) return true // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true // 169.254.0.0/16 link-local & cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12 RFC1918
    if (a === 192 && b === 168) return true // 192.168.0.0/16 RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10 CGNAT
    if (a >= 224) return true // multicast / reserved
    return false
  }

  if (net.isIPv6(normalized)) {
    if (normalized === '::' || normalized === '::1') return true
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true // ULA fc00::/7
    if (
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb')
    ) {
      return true // Link-local fe80::/10
    }
    if (normalized.startsWith('ff')) return true // Multicast
    return false
  }

  return true
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata',
])

export interface DnsLookupLike {
  lookup(
    hostname: string,
    options: { all: true },
  ): Promise<Array<{ address: string; family: number }>>
}

/**
 * Validates outbound webhook URLs against SSRF (blocking private IPs,
 * loopback, Docker bridge hosts, and cloud metadata endpoints).
 * Set ALLOW_PRIVATE_WEBHOOKS=true only if intentionally delivering to
 * a trusted internal LAN relay (e.g., self-hosted n8n).
 */
export async function assertSafeWebhookUrl(
  rawUrl: string,
  resolver: DnsLookupLike = dns,
): Promise<URL> {
  let parsed: URL
  try {
    parsed = new URL(rawUrl.trim())
  } catch {
    throw new Error('Invalid webhook URL format.')
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Webhook URL must use https:// or http://.')
  }

  const cfg = getConfig()
  if (cfg.allowPrivateWebhooks) {
    return parsed
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(
      'Webhook URLs must use https:// (set ALLOW_PRIVATE_WEBHOOKS=true only for trusted internal HTTP relays).',
    )
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.localhost')
  ) {
    throw new Error(
      `Webhook hostname "${hostname}" is blocked by SSRF protection.`,
    )
  }

  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error(
        `Webhook IP "${hostname}" is private or reserved and blocked by SSRF protection.`,
      )
    }
    return parsed
  }

  let resolved: Array<{ address: string; family: number }>
  try {
    resolved = await resolver.lookup(hostname, { all: true })
  } catch {
    throw new Error(`Could not resolve webhook hostname "${hostname}".`)
  }

  if (resolved.length === 0) {
    throw new Error(`Webhook hostname "${hostname}" resolved to no addresses.`)
  }

  for (const entry of resolved) {
    if (isPrivateOrReservedIp(entry.address)) {
      throw new Error(
        `Webhook hostname "${hostname}" resolved to private/reserved address ${entry.address} and was blocked by SSRF protection.`,
      )
    }
  }

  return parsed
}
