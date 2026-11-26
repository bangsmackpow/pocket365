import { drizzle, type DrizzleD1Database } from 'drizzle-orm/d1'
import { getCloudflareEnv } from '~/server/cf/env'
import * as schema from './schema'

export type Pocket365Db = DrizzleD1Database<typeof schema>

let cachedD1Ref: D1Database | null = null
let cachedDb: Pocket365Db | null = null
let testD1Override: D1Database | null = null

export function setTestD1(d1: D1Database | null): void {
  testD1Override = d1
  cachedD1Ref = null
  cachedDb = null
}

export function getRawD1(): D1Database {
  const d1 = testD1Override ?? getCloudflareEnv().DB
  if (!d1) {
    throw new Error(
      'Cloudflare D1 binding "DB" is not available. Configure d1_databases in wrangler.jsonc or call initDbForTesting() in unit tests.',
    )
  }
  return d1
}

export function getDb(): Pocket365Db {
  const d1 = getRawD1()
  if (cachedDb && cachedD1Ref === d1) {
    return cachedDb
  }
  cachedD1Ref = d1
  cachedDb = drizzle(d1, { schema })
  return cachedDb
}

export async function checkDatabaseHealth(): Promise<{
  ok: boolean
  error?: string
}> {
  try {
    const d1 = getRawD1()
    const row = await d1.prepare('SELECT 1 AS ok').first<{ ok: number }>()
    return { ok: row?.ok === 1 }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'D1 connectivity error',
    }
  }
}

export function closeDb(): void {
  testD1Override = null
  cachedD1Ref = null
  cachedDb = null
}
