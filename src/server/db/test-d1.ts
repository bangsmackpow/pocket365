import { DatabaseSync, type SQLInputValue } from 'node:sqlite'
import {
  clearTestCloudflareEnv,
  setTestCloudflareEnv,
} from '~/server/cf/env'
import { clearMemoryKvForTests } from '~/server/cf/kv'
import { clearMemoryR2ForTests } from '~/server/cf/r2'
import { closeDb, getDb, setTestD1, type Pocket365Db } from './index'
import { MIGRATIONS } from './migrate'

let activeSqlite: DatabaseSync | null = null

function normalizeParam(value: unknown): SQLInputValue {
  if (value === undefined || value === null) return null
  if (typeof value === 'boolean') return value ? 1 : 0
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    value instanceof Uint8Array
  ) {
    return value
  }
  return String(value)
}

/**
 * Wraps Node 22's built-in `node:sqlite` (`DatabaseSync`) in a spec-compliant
 * Cloudflare `D1Database` interface so Vitest runs the exact same `drizzle-orm/d1`
 * async driver and migrations as production Cloudflare Workers without native deps.
 */
function createMemoryD1(sqlite: DatabaseSync): D1Database {
  const makePrepared = (sql: string, boundParams: SQLInputValue[] = []) => {
    const stmt: D1PreparedStatement = {
      bind(...values: unknown[]): D1PreparedStatement {
        return makePrepared(sql, values.map(normalizeParam))
      },
      async first<T = unknown>(colName?: string): Promise<T | null> {
        const prepared = sqlite.prepare(sql)
        const row = prepared.get(...boundParams) as
          | Record<string, unknown>
          | undefined
        if (!row) return null
        if (colName) {
          return (row[colName] as T) ?? null
        }
        return { ...row } as T
      },
      async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        const prepared = sqlite.prepare(sql)
        const info = prepared.run(...boundParams)
        return {
          results: [] as T[],
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: 0,
            rows_written: Number(info.changes ?? 0),
            last_row_id: Number(info.lastInsertRowid ?? 0),
            changed_db: Number(info.changes ?? 0) > 0,
            changes: Number(info.changes ?? 0),
          },
        }
      },
      async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        const prepared = sqlite.prepare(sql)
        const rows = prepared.all(...boundParams) as Record<string, unknown>[]
        const plainRows = rows.map((r) => ({ ...r })) as T[]
        return {
          results: plainRows,
          success: true,
          meta: {
            duration: 0,
            size_after: 0,
            rows_read: plainRows.length,
            rows_written: 0,
            last_row_id: 0,
            changed_db: false,
            changes: 0,
          },
        }
      },
      raw: (async (options?: { columnNames?: boolean }) => {
        const prepared = sqlite.prepare(sql)
        const rows = prepared.all(...boundParams) as Record<string, unknown>[]
        const result: unknown[][] = []
        if (options?.columnNames && rows.length > 0) {
          result.push(Object.keys(rows[0]!))
        }
        for (const row of rows) {
          result.push(Object.values(row))
        }
        return result
      }) as D1PreparedStatement['raw'],
    }
    return stmt
  }

  const d1: D1Database = {
    prepare(query: string): D1PreparedStatement {
      return makePrepared(query)
    },
    async batch<T = unknown>(
      statements: D1PreparedStatement[],
    ): Promise<D1Result<T>[]> {
      const results: D1Result<T>[] = []
      for (const s of statements) {
        results.push(await s.all<T>())
      }
      return results
    },
    async exec(query: string): Promise<D1ExecResult> {
      sqlite.exec(query)
      return { count: 1, duration: 0 }
    },
    withSession(): D1DatabaseSession {
      throw new Error('D1DatabaseSession not implemented in memory test shim')
    },
    async dump(): Promise<ArrayBuffer> {
      return new ArrayBuffer(0)
    },
  }

  return d1
}

export function initDbForTesting(): Pocket365Db {
  closeTestDb()
  const sqlite = new DatabaseSync(':memory:')
  sqlite.exec('PRAGMA foreign_keys = ON;')
  for (const migration of MIGRATIONS) {
    sqlite.exec(migration.sql)
  }
  activeSqlite = sqlite
  const memD1 = createMemoryD1(sqlite)
  setTestD1(memD1)
  setTestCloudflareEnv({ DB: memD1 })
  clearMemoryKvForTests()
  clearMemoryR2ForTests()
  return getDb()
}

export function closeTestDb(): void {
  closeDb()
  clearTestCloudflareEnv()
  clearMemoryKvForTests()
  clearMemoryR2ForTests()
  if (activeSqlite) {
    try {
      activeSqlite.close()
    } catch {
      // Ignore already-closed handle
    }
    activeSqlite = null
  }
}
