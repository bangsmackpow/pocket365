import { exportPKCS8, generateKeyPair, decodeProtectedHeader } from 'jose'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createClientAssertionJwt, GraphTokenProvider } from './auth'
import {
  computeBackoffMs,
  MicrosoftGraphClient,
  parseRetryAfterMs,
} from './client'
import { enqueueJob, processNextQueuedJob, retryFailedJob } from './jobs'
import { resetConfigCache } from '~/server/config'
import { listAuditLogs } from '~/server/db/audit'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'

describe('Microsoft Graph Client, Auth & Async Job Runner', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      ENTRA_TENANT_ID: '11111111-2222-3333-4444-555555555555',
      GRAPH_CLIENT_ID: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      GRAPH_CLIENT_SECRET: 'graph-test-secret',
      GRAPH_MAX_RETRIES: '3',
      GRAPH_BASE_BACKOFF_MS: '50',
    }
    resetConfigCache()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('builds a valid RS256 X.509 client assertion JWT with x5t header', async () => {
    const { privateKey } = await generateKeyPair('RS256', { extractable: true })
    const pem = await exportPKCS8(privateKey)
    const thumbprint = '0123456789abcdef0123456789abcdef01234567'

    const jwt = await createClientAssertionJwt({
      clientId: 'client-123',
      tokenUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      thumbprintHex: thumbprint,
      privateKeyPem: pem,
    })

    const header = decodeProtectedHeader(jwt)
    expect(header.alg).toBe('RS256')
    expect(header.x5t).toBe(Buffer.from(thumbprint, 'hex').toString('base64url'))
  })

  it('parses Retry-After headers and handles 429 throttling with retries', async () => {
    expect(parseRetryAfterMs('2')).toBe(2000)
    expect(computeBackoffMs(0, 500, '3')).toBe(3000)

    const tokenFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ access_token: 'tok-1', expires_in: 3600 }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    const sleepCalls: number[] = []
    const graphFetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: { code: 'TooManyRequests' } }), {
          status: 429,
          headers: { 'Retry-After': '2' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: { code: 'ServiceUnavailable' } }), {
          status: 503,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ value: [{ id: 'u1', displayName: 'Alice' }] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )

    const provider = new GraphTokenProvider(tokenFetch)
    const client = new MicrosoftGraphClient({
      tokenProvider: provider,
      fetchImpl: graphFetch,
      sleepImpl: async (ms) => {
        sleepCalls.push(ms)
      },
      maxRetries: 3,
      baseBackoffMs: 100,
    })

    const result = await client.listUsers({ top: 10 })
    expect(result.items).toHaveLength(1)
    expect(result.items[0]?.displayName).toBe('Alice')
    expect(graphFetch).toHaveBeenCalledTimes(3)
    expect(tokenFetch).toHaveBeenCalledTimes(1)
    expect(sleepCalls[0]).toBe(2000)
    expect(sleepCalls[1]).toBeGreaterThanOrEqual(200)
  })

  it('processes D1 async bulk jobs and records audit trail', async () => {
    const fakeGraph = {
      setUserAccountEnabled: vi
        .fn()
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error('Directory object not found')),
    } as unknown as MicrosoftGraphClient

    const actor = {
      oid: 'admin-oid',
      upn: 'admin@contoso.com',
      role: 'admin' as const,
    }

    const queued = await enqueueJob({
      type: 'user.bulk_toggle_enabled',
      payload: { userIds: ['u-1', 'u-2'], accountEnabled: false },
      actor,
      autoStartWorker: false,
    })

    expect(queued.status).toBe('queued')

    const finished = await processNextQueuedJob(fakeGraph, 0)
    expect(finished?.status).toBe('completed')
    const parsedResult = JSON.parse(finished!.resultJson!)
    expect(parsedResult.total).toBe(2)
    expect(parsedResult.succeeded).toBe(1)
    expect(parsedResult.failed).toBe(1)

    const audits = await listAuditLogs({ limit: 10 })
    expect(
      audits.some((a) => a.action === 'job.enqueue:user.bulk_toggle_enabled'),
    ).toBe(true)
    expect(
      audits.some((a) => a.action === 'job.complete:user.bulk_toggle_enabled'),
    ).toBe(true)

    const failingGraph = {
      setUserAccountEnabled: vi.fn().mockRejectedValue(new Error('Forbidden')),
    } as unknown as MicrosoftGraphClient

    const job2 = await enqueueJob({
      type: 'user.bulk_toggle_enabled',
      payload: { userIds: ['u-9'], accountEnabled: true },
      actor,
      autoStartWorker: false,
    })
    const failedJob = await processNextQueuedJob(failingGraph, 0)
    expect(failedJob?.status).toBe('failed')

    const retried = await retryFailedJob(job2.id, actor)
    expect(['queued', 'running', 'failed']).toContain(retried.status)
  })
})
