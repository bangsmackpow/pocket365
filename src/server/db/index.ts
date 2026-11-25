import fs from 'node:fs'
import path from 'node:path'
import Database from 'better-sqlite3'
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3'
import { getConfig } from '~/server/config'
import * as schema from './schema'
import { runMigrations } from './migrate'

export type Pocket365Db = BetterSQLite3Database<typeof schema>

let sqliteInstance: Database.Database | null = null
let dbInstance: Pocket365Db | null = null
let activeDbPath: string | null = null

export function resolveDbPath(): string {
  const cfg = getConfig()
  return path.join(cfg.dataDir, 'pocket365.db')
}

function initializeDatabase(dbPath: string): {
  sqlite: Database.Database
  db: Pocket365Db
} {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true })
  }

  const sqlite = new Database(dbPath)
  sqlite.pragma('journal_mode = WAL')
  sqlite.pragma('busy_timeout = 5000')
  sqlite.pragma('foreign_keys = ON')
  sqlite.pragma('synchronous = NORMAL')

  runMigrations(sqlite)

  const db = drizzle(sqlite, { schema })
  return { sqlite, db }
}

export function getSqlite(): Database.Database {
  if (!sqliteInstance) {
    const dbPath = activeDbPath ?? resolveDbPath()
    const initialized = initializeDatabase(dbPath)
    sqliteInstance = initialized.sqlite
    dbInstance = initialized.db
    activeDbPath = dbPath
  }
  return sqliteInstance
}

export function getDb(): Pocket365Db {
  if (!dbInstance) {
    getSqlite()
  }
  return dbInstance!
}

export function checkDatabaseHealth(): { ok: boolean; error?: string } {
  try {
    const sqlite = getSqlite()
    const row = sqlite.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined
    return { ok: row?.ok === 1 }
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'Database connectivity error',
    }
  }
}

export function closeDb(): void {
  if (sqliteInstance) {
    sqliteInstance.close()
    sqliteInstance = null
    dbInstance = null
    activeDbPath = null
  }
}

export function initDbForTesting(dbPath = ':memory:'): Pocket365Db {
  closeDb()
  activeDbPath = dbPath
  return getDb()
}
