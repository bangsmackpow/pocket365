import {
  getRequest,
  setResponseHeader,
  setResponseStatus,
} from '@tanstack/react-start/server'
import { getCloudflareEnv } from '~/server/cf/env'
import { kvGetJson, kvPutJson } from '~/server/cf/kv'
import { getClientIp } from '~/server/http/proxy'

export type RateLimitBucket = 'auth' | 'api' | 'mutation' | 'heavy'

interface BucketConfig {
  limit: number
  windowMs: number
}

const DEFAULT_BUCKETS: Record<RateLimitBucket, BucketConfig> = {
  auth: { limit: 20, windowMs: 10 * 60 * 1000 }, // 20 req / 10 min per IP
  api: { limit: 180, windowMs: 60 * 1000 }, // 180 req / min per caller
  mutation: { limit: 60, windowMs: 60 * 1000 }, // 60 mutations / min per caller
  heavy: { limit: 8, windowMs: 5 * 60 * 1000 }, // 8 heavy scans/sweeps / 5 min
}

export class RateLimitHttpError extends Error {
  public readonly status = 429
  public readonly retryAfterSeconds: number

  constructor(retryAfterSeconds: number, message?: string) {
    super(
      message ||
        `Rate limit exceeded. Retry after ${retryAfterSeconds} second(s).`,
    )
    this.name = 'RateLimitHttpError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export interface RateLimitResult {
  allowed: boolean
  limit: number
  remaining: number
  resetAt: number
  retryAfterSeconds: number
}

class SlidingWindowLimiter {
  private readonly store = new Map<string, number[]>()
  private lastPrune = Date.now()

  public check(
    key: string,
    limit: number,
    windowMs: number,
    nowMs = Date.now(),
  ): RateLimitResult {
    this.maybePrune(nowMs)

    const cutoff = nowMs - windowMs
    const existing = (this.store.get(key) ?? []).filter((ts) => ts > cutoff)

    if (existing.length >= limit) {
      const oldest = existing[0] ?? nowMs
      const resetAt = oldest + windowMs
      const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - nowMs) / 1000))
      this.store.set(key, existing)
      return {
        allowed: false,
        limit,
        remaining: 0,
        resetAt,
        retryAfterSeconds,
      }
    }

    existing.push(nowMs)
    this.store.set(key, existing)
    return {
      allowed: true,
      limit,
      remaining: Math.max(0, limit - existing.length),
      resetAt: nowMs + windowMs,
      retryAfterSeconds: 0,
    }
  }

  public resetAll(): void {
    this.store.clear()
  }

  private maybePrune(nowMs: number): void {
    if (nowMs - this.lastPrune < 60_000) return
    this.lastPrune = nowMs
    const maxWindow = 15 * 60 * 1000
    for (const [k, timestamps] of this.store.entries()) {
      const kept = timestamps.filter((ts) => ts > nowMs - maxWindow)
      if (kept.length === 0) this.store.delete(k)
      else this.store.set(k, kept)
    }
  }
}

const limiter = new SlidingWindowLimiter()

export function resetRateLimiterForTests(): void {
  limiter.resetAll()
}

export function checkRateLimit(
  bucket: RateLimitBucket,
  subjectKey: string,
  override?: Partial<BucketConfig>,
  nowMs?: number,
): RateLimitResult {
  const cfg = {
    ...DEFAULT_BUCKETS[bucket],
    ...override,
  }
  return limiter.check(`${bucket}:${subjectKey}`, cfg.limit, cfg.windowMs, nowMs)
}

/**
 * Edge-distributed rate limit check backed by Cloudflare KV (`POCKET365_KV`)
 * when bound, falling back to isolate-local sliding-window memory limiter.
 */
export async function checkRateLimitAsync(
  bucket: RateLimitBucket,
  subjectKey: string,
  override?: Partial<BucketConfig>,
  nowMs = Date.now(),
): Promise<RateLimitResult> {
  const cfg = {
    ...DEFAULT_BUCKETS[bucket],
    ...override,
  }

  if (!getCloudflareEnv().POCKET365_KV) {
    return limiter.check(`${bucket}:${subjectKey}`, cfg.limit, cfg.windowMs, nowMs)
  }

  const kvKey = `rl:${bucket}:${subjectKey}`
  const cutoff = nowMs - cfg.windowMs
  const stored = (await kvGetJson<number[]>(kvKey)) ?? []
  const existing = stored.filter((ts) => ts > cutoff)

  if (existing.length >= cfg.limit) {
    const oldest = existing[0] ?? nowMs
    const resetAt = oldest + cfg.windowMs
    const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - nowMs) / 1000))
    return {
      allowed: false,
      limit: cfg.limit,
      remaining: 0,
      resetAt,
      retryAfterSeconds,
    }
  }

  existing.push(nowMs)
  const ttlSec = Math.max(60, Math.ceil(cfg.windowMs / 1000))
  await kvPutJson(kvKey, existing, ttlSec)

  return {
    allowed: true,
    limit: cfg.limit,
    remaining: Math.max(0, cfg.limit - existing.length),
    resetAt: nowMs + cfg.windowMs,
    retryAfterSeconds: 0,
  }
}

export function enforceRateLimit(
  bucket: RateLimitBucket,
  subjectKey?: string,
  explicitRequest?: Request,
): RateLimitResult {
  let req = explicitRequest
  if (!req) {
    try {
      req = getRequest()
    } catch {
      req = undefined
    }
  }

  const key = subjectKey || getClientIp(req) || 'unknown'
  const res = checkRateLimit(bucket, key)

  if (!res.allowed) {
    try {
      setResponseStatus(429)
      setResponseHeader('Retry-After', String(res.retryAfterSeconds))
    } catch {
      // Outside TanStack Start server request context
    }
    throw new RateLimitHttpError(res.retryAfterSeconds)
  }

  return res
}

export async function enforceRateLimitAsync(
  bucket: RateLimitBucket,
  subjectKey?: string,
  explicitRequest?: Request,
): Promise<RateLimitResult> {
  let req = explicitRequest
  if (!req) {
    try {
      req = getRequest()
    } catch {
      req = undefined
    }
  }

  const key = subjectKey || getClientIp(req) || 'unknown'
  const res = await checkRateLimitAsync(bucket, key)

  if (!res.allowed) {
    try {
      setResponseStatus(429)
      setResponseHeader('Retry-After', String(res.retryAfterSeconds))
    } catch {
      // Outside TanStack Start server request context
    }
    throw new RateLimitHttpError(res.retryAfterSeconds)
  }

  return res
}

export function rateLimitResponse(result: RateLimitResult): Response {
  return Response.json(
    {
      error: 'TOO_MANY_REQUESTS',
      message: `Rate limit exceeded. Retry after ${result.retryAfterSeconds} second(s).`,
      retryAfterSeconds: result.retryAfterSeconds,
    },
    {
      status: 429,
      headers: {
        'Retry-After': String(result.retryAfterSeconds),
        'X-RateLimit-Limit': String(result.limit),
        'X-RateLimit-Remaining': '0',
      },
    },
  )
}
