import dns from 'node:dns/promises'

export interface DomainEmailAuthAudit {
  domain: string
  spfRecord: string | null
  spfStatus: 'pass' | 'warn' | 'fail'
  spfDetail: string
  dmarcRecord: string | null
  dmarcPolicy: 'reject' | 'quarantine' | 'none' | 'missing'
  dmarcStatus: 'pass' | 'warn' | 'fail'
  dmarcDetail: string
  dkimSelector1: string | null
  dkimSelector2: string | null
  dkimStatus: 'pass' | 'warn' | 'fail'
  dkimDetail: string
}

export interface DnsResolverLike {
  resolveTxt(hostname: string): Promise<string[][]>
  resolveCname(hostname: string): Promise<string[]>
}

export function evaluateSpfRecord(txtRecords: string[]): {
  record: string | null
  status: 'pass' | 'warn' | 'fail'
  detail: string
} {
  const spf = txtRecords.find((r) => /^v=spf1\b/i.test(r.trim())) ?? null
  if (!spf) {
    return {
      record: null,
      status: 'fail',
      detail: 'No SPF TXT record found (v=spf1 ...).',
    }
  }
  const lower = spf.toLowerCase()
  if (lower.includes('+all')) {
    return {
      record: spf,
      status: 'fail',
      detail: 'SPF uses "+all" which allows anyone on the internet to spoof this domain.',
    }
  }
  if (!lower.includes('-all') && !lower.includes('~all')) {
    return {
      record: spf,
      status: 'warn',
      detail: 'SPF record should end with "-all" (hard fail) or "~all" (soft fail).',
    }
  }
  if (!lower.includes('spf.protection.outlook.com')) {
    return {
      record: spf,
      status: 'warn',
      detail: 'SPF present, but does not include spf.protection.outlook.com.',
    }
  }
  return {
    record: spf,
    status: 'pass',
    detail: lower.includes('-all')
      ? 'SPF configured with strict hard-fail (-all).'
      : 'SPF configured with soft-fail (~all); consider tightening to -all after testing.',
  }
}

export function evaluateDmarcRecord(txtRecords: string[]): {
  record: string | null
  policy: 'reject' | 'quarantine' | 'none' | 'missing'
  status: 'pass' | 'warn' | 'fail'
  detail: string
} {
  const dmarc = txtRecords.find((r) => /^v=dmarc1\b/i.test(r.trim())) ?? null
  if (!dmarc) {
    return {
      record: null,
      policy: 'missing',
      status: 'fail',
      detail: 'No _dmarc TXT record found.',
    }
  }
  const match = dmarc.match(/\bp\s*=\s*(reject|quarantine|none)\b/i)
  const policy = (match?.[1]?.toLowerCase() ?? 'none') as
    | 'reject'
    | 'quarantine'
    | 'none'

  if (policy === 'reject' || policy === 'quarantine') {
    return {
      record: dmarc,
      policy,
      status: 'pass',
      detail: `DMARC enforcing p=${policy}.`,
    }
  }
  return {
    record: dmarc,
    policy: 'none',
    status: 'warn',
    detail: 'DMARC is monitor-only (p=none). Upgrade to p=quarantine or p=reject per CIS 2.1.8.',
  }
}

async function safeResolveTxt(
  resolver: DnsResolverLike,
  hostname: string,
): Promise<string[]> {
  try {
    const chunks = await resolver.resolveTxt(hostname)
    return chunks.map((parts) => parts.join(''))
  } catch {
    return []
  }
}

async function safeResolveCname(
  resolver: DnsResolverLike,
  hostname: string,
): Promise<string | null> {
  try {
    const records = await resolver.resolveCname(hostname)
    return records[0] ?? null
  } catch {
    return null
  }
}

export async function auditDomainEmailAuth(
  domain: string,
  resolver: DnsResolverLike = dns,
): Promise<DomainEmailAuthAudit> {
  const [rootTxt, dmarcTxt, sel1, sel2] = await Promise.all([
    safeResolveTxt(resolver, domain),
    safeResolveTxt(resolver, `_dmarc.${domain}`),
    safeResolveCname(resolver, `selector1._domainkey.${domain}`),
    safeResolveCname(resolver, `selector2._domainkey.${domain}`),
  ])

  const spf = evaluateSpfRecord(rootTxt)
  const dmarc = evaluateDmarcRecord(dmarcTxt)

  let dkimStatus: 'pass' | 'warn' | 'fail' = 'fail'
  let dkimDetail =
    'Neither selector1._domainkey nor selector2._domainkey CNAME found.'
  if (sel1 && sel2) {
    dkimStatus = 'pass'
    dkimDetail = 'Both Microsoft 365 DKIM selectors (selector1 & selector2) configured.'
  } else if (sel1 || sel2) {
    dkimStatus = 'warn'
    dkimDetail = 'Only one DKIM selector CNAME found; publish both selector1 & selector2 for key rotation.'
  }

  return {
    domain,
    spfRecord: spf.record,
    spfStatus: spf.status,
    spfDetail: spf.detail,
    dmarcRecord: dmarc.record,
    dmarcPolicy: dmarc.policy,
    dmarcStatus: dmarc.status,
    dmarcDetail: dmarc.detail,
    dkimSelector1: sel1,
    dkimSelector2: sel2,
    dkimStatus,
    dkimDetail,
  }
}
