import { getCloudflareEnv } from './env'

interface MemoryKvEntry {
  value: string
  expiresAt: number | null
}

const memoryKv = new Map<string, MemoryKvEntry>()

function getKvBinding(): KVNamespace | null {
  return getCloudflareEnv().POCKET365_KV ?? null
}

export function clearMemoryKvForTests(): void {
  memoryKv.clear()
}

export async function kvGet(key: string): Promise<string | null> {
  const kv = getKvBinding()
  if (kv) {
    return kv.get(key, 'text')
  }
  const entry = memoryKv.get(key)
  if (!entry) return null
  if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
    memoryKv.delete(key)
    return null
  }
  return entry.value
}

export async function kvPut(
  key: string,
  value: string,
  ttlSeconds?: number,
): Promise<void> {
  const kv = getKvBinding()
  // Cloudflare KV enforces a minimum expirationTtl of 60 seconds
  const safeTtl =
    typeof ttlSeconds === 'number' && Number.isFinite(ttlSeconds)
      ? Math.max(60, Math.ceil(ttlSeconds))
      : undefined

  if (kv) {
    await kv.put(key, value, safeTtl ? { expirationTtl: safeTtl } : undefined)
    return
  }

  memoryKv.set(key, {
    value,
    expiresAt:
      typeof ttlSeconds === 'number' && ttlSeconds > 0
        ? Date.now() + ttlSeconds * 1000
        : null,
  })
}

export async function kvDelete(key: string): Promise<void> {
  const kv = getKvBinding()
  if (kv) {
    await kv.delete(key)
    return
  }
  memoryKv.delete(key)
}

export async function kvGetJson<T>(key: string): Promise<T | null> {
  const raw = await kvGet(key)
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

export async function kvPutJson(
  key: string,
  value: unknown,
  ttlSeconds?: number,
): Promise<void> {
  await kvPut(key, JSON.stringify(value), ttlSeconds)
}
