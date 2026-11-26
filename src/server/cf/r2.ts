import { getCloudflareEnv } from './env'

interface MemoryR2Entry {
  body: string
  contentType: string
  customMetadata: Record<string, string>
  uploadedAt: number
}

const memoryR2 = new Map<string, MemoryR2Entry>()

function getR2Binding(): R2Bucket | null {
  return getCloudflareEnv().POCKET365_R2 ?? null
}

export function clearMemoryR2ForTests(): void {
  memoryR2.clear()
}

export interface StoredExportMetadata {
  key: string
  size: number
  contentType: string
  uploadedAt: string
  customMetadata: Record<string, string>
}

export async function putExportObject(params: {
  key: string
  body: string
  contentType: string
  customMetadata?: Record<string, string>
}): Promise<StoredExportMetadata> {
  const r2 = getR2Binding()
  const metadata = params.customMetadata ?? {}

  if (r2) {
    const obj = await r2.put(params.key, params.body, {
      httpMetadata: { contentType: params.contentType },
      customMetadata: metadata,
    })
    return {
      key: params.key,
      size: obj?.size ?? params.body.length,
      contentType: params.contentType,
      uploadedAt: (obj?.uploaded ?? new Date()).toISOString(),
      customMetadata: metadata,
    }
  }

  const now = Date.now()
  memoryR2.set(params.key, {
    body: params.body,
    contentType: params.contentType,
    customMetadata: metadata,
    uploadedAt: now,
  })

  return {
    key: params.key,
    size: new TextEncoder().encode(params.body).byteLength,
    contentType: params.contentType,
    uploadedAt: new Date(now).toISOString(),
    customMetadata: metadata,
  }
}

export async function getExportObject(key: string): Promise<{
  body: string
  contentType: string
  customMetadata: Record<string, string>
} | null> {
  const r2 = getR2Binding()
  if (r2) {
    const obj = await r2.get(key)
    if (!obj) return null
    return {
      body: await obj.text(),
      contentType: obj.httpMetadata?.contentType ?? 'application/octet-stream',
      customMetadata: obj.customMetadata ?? {},
    }
  }

  const entry = memoryR2.get(key)
  if (!entry) return null
  return {
    body: entry.body,
    contentType: entry.contentType,
    customMetadata: entry.customMetadata,
  }
}

export async function listExportObjects(
  prefix: string,
  limit = 50,
): Promise<StoredExportMetadata[]> {
  const r2 = getR2Binding()
  if (r2) {
    const listed = await r2.list({ prefix, limit })
    return listed.objects.map((o) => ({
      key: o.key,
      size: o.size,
      contentType: o.httpMetadata?.contentType ?? 'application/octet-stream',
      uploadedAt: o.uploaded.toISOString(),
      customMetadata: o.customMetadata ?? {},
    }))
  }

  const out: StoredExportMetadata[] = []
  for (const [key, entry] of memoryR2.entries()) {
    if (!key.startsWith(prefix)) continue
    out.push({
      key,
      size: new TextEncoder().encode(entry.body).byteLength,
      contentType: entry.contentType,
      uploadedAt: new Date(entry.uploadedAt).toISOString(),
      customMetadata: entry.customMetadata,
    })
  }
  return out
    .sort((a, b) => Date.parse(b.uploadedAt) - Date.parse(a.uploadedAt))
    .slice(0, limit)
}
