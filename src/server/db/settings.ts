import { z } from 'zod'
import { getDb } from './index'
import { appSettings } from './schema'

export const runtimeSettingsSchema = z.object({
  defaultPageSize: z.number().int().min(10).max(100),
  auditRetentionDays: z.number().int().min(7).max(3650),
  organizationBanner: z.string().max(240),
  bulkJobDelayMs: z.number().int().min(0).max(5000),
})

export type RuntimeSettings = z.infer<typeof runtimeSettingsSchema>

export const DEFAULT_RUNTIME_SETTINGS: RuntimeSettings = {
  defaultPageSize: 25,
  auditRetentionDays: 90,
  organizationBanner: '',
  bulkJobDelayMs: 150,
}

export function getRuntimeSettings(): RuntimeSettings {
  const db = getDb()
  const rows = db.select().from(appSettings).all()
  const merged: Record<string, unknown> = { ...DEFAULT_RUNTIME_SETTINGS }

  for (const row of rows) {
    if (row.key in DEFAULT_RUNTIME_SETTINGS) {
      try {
        merged[row.key] = JSON.parse(row.valueJson)
      } catch {
        // Keep default if stored JSON is malformed
      }
    }
  }

  const parsed = runtimeSettingsSchema.safeParse(merged)
  return parsed.success ? parsed.data : DEFAULT_RUNTIME_SETTINGS
}

export function updateRuntimeSettings(
  updates: Partial<RuntimeSettings>,
  updatedBy: string,
): RuntimeSettings {
  const current = getRuntimeSettings()
  const next = runtimeSettingsSchema.parse({
    ...current,
    ...updates,
  })

  const db = getDb()
  const now = Date.now()
  const entries = Object.entries(next) as Array<[keyof RuntimeSettings, unknown]>

  for (const [key, value] of entries) {
    db.insert(appSettings)
      .values({
        key,
        valueJson: JSON.stringify(value),
        updatedBy,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: appSettings.key,
        set: {
          valueJson: JSON.stringify(value),
          updatedBy,
          updatedAt: now,
        },
      })
      .run()
  }

  return next
}
