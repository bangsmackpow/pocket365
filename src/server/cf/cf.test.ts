import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import { checkDatabaseHealth } from '~/server/db'
import { kvDelete, kvGetJson, kvPutJson } from './kv'
import { getExportObject, listExportObjects, putExportObject } from './r2'
import { handleCloudflareScheduled } from './handlers'

describe('Cloudflare Full-Stack Runtime (D1, KV, R2, Cron)', () => {
  beforeEach(() => {
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
  })

  it('verifies D1 health check, KV JSON storage, and R2 report archiving', async () => {
    const health = await checkDatabaseHealth()
    expect(health.ok).toBe(true)

    await kvPutJson('test:key', { ok: true, count: 3 }, 120)
    expect(await kvGetJson<{ ok: boolean; count: number }>('test:key')).toEqual({
      ok: true,
      count: 3,
    })
    await kvDelete('test:key')
    expect(await kvGetJson('test:key')).toBeNull()

    await putExportObject({
      key: 'exports/cis/report-1.json',
      body: JSON.stringify({ scorePct: 92 }),
      contentType: 'application/json',
      customMetadata: { actorUpn: 'admin@contoso.com' },
    })
    const fetched = await getExportObject('exports/cis/report-1.json')
    expect(fetched?.contentType).toBe('application/json')
    expect(JSON.parse(fetched!.body)).toEqual({ scorePct: 92 })

    const listed = await listExportObjects('exports/cis/')
    expect(listed.some((o) => o.key === 'exports/cis/report-1.json')).toBe(true)
  })

  it('runs Cloudflare Cron scheduled sweep safely without throwing', async () => {
    const result = await handleCloudflareScheduled({})
    expect(result.jobsProcessed).toBe(0)
    expect(result.alertsTriggered).toBe(0)
  })
})
