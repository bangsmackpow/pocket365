/**
 * Cloudflare Workers-compatible DNS-over-HTTPS (DoH) resolver.
 * Uses Cloudflare's public DoH JSON endpoint (`https://cloudflare-dns.com/dns-query`)
 * with zero Node.js `node:dns` dependencies.
 */

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query'

interface DohAnswer {
  name: string
  type: number
  TTL: number
  data: string
}

interface DohResponse {
  Status: number
  Answer?: DohAnswer[]
}

async function queryDoh(
  hostname: string,
  recordType: 'A' | 'AAAA' | 'TXT' | 'CNAME',
  fetchImpl: typeof fetch = fetch,
): Promise<DohAnswer[]> {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(hostname)}&type=${recordType}`
  const rawFetch = fetchImpl ?? globalThis.fetch
  const res = await rawFetch.call(globalThis, url, {
    method: 'GET',
    headers: { Accept: 'application/dns-json' },
  })
  if (!res.ok) {
    throw new Error(`DNS-over-HTTPS query failed (${res.status}) for ${hostname} ${recordType}`)
  }
  const data = (await res.json()) as DohResponse
  if (data.Status !== 0 || !Array.isArray(data.Answer)) {
    return []
  }
  return data.Answer
}

function unquoteTxtData(raw: string): string {
  // DoH returns TXT records quoted, sometimes split into multiple quoted strings: "v=spf1 " "include:..."
  const matches = raw.match(/"((?:\\.|[^"\\])*)"/g)
  if (!matches) return raw.replace(/^"|"$/g, '')
  return matches
    .map((segment) =>
      segment
        .slice(1, -1)
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\'),
    )
    .join('')
}

export const dohDnsResolver = {
  async resolveTxt(hostname: string): Promise<string[][]> {
    const answers = await queryDoh(hostname, 'TXT')
    return answers
      .filter((a) => a.type === 16)
      .map((a) => [unquoteTxtData(a.data)])
  },
  async resolveCname(hostname: string): Promise<string[]> {
    const answers = await queryDoh(hostname, 'CNAME')
    return answers
      .filter((a) => a.type === 5)
      .map((a) => a.data.replace(/\.$/, ''))
  },
}

export const dohDnsLookup = {
  async lookup(
    hostname: string,
    _options: { all: true },
  ): Promise<Array<{ address: string; family: number }>> {
    const [aRecords, aaaaRecords] = await Promise.all([
      queryDoh(hostname, 'A').catch(() => [] as DohAnswer[]),
      queryDoh(hostname, 'AAAA').catch(() => [] as DohAnswer[]),
    ])

    const results: Array<{ address: string; family: number }> = []
    for (const a of aRecords) {
      if (a.type === 1 && a.data) {
        results.push({ address: a.data.trim(), family: 4 })
      }
    }
    for (const aaaa of aaaaRecords) {
      if (aaaa.type === 28 && aaaa.data) {
        results.push({ address: aaaa.data.trim(), family: 6 })
      }
    }
    return results
  },
}
