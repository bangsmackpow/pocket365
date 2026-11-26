export interface Pocket365QueueMessage {
  kind: 'job'
  jobId: string
  organizationId?: string
}

export interface CloudflareEnv {
  DB?: D1Database
  POCKET365_KV?: KVNamespace
  POCKET365_R2?: R2Bucket
  POCKET365_QUEUE?: Queue<Pocket365QueueMessage>
  ASSETS?: Fetcher
  [key: string]: unknown
}

declare global {
  var __env__: CloudflareEnv | undefined
}

let testEnvOverride: CloudflareEnv | null = null
let activeWaitUntil: ((promise: Promise<unknown>) => void) | null = null

export function setTestCloudflareEnv(env: CloudflareEnv): void {
  testEnvOverride = env
}

export function clearTestCloudflareEnv(): void {
  testEnvOverride = null
}

export function getCloudflareEnv(): CloudflareEnv {
  if (testEnvOverride) {
    return testEnvOverride
  }
  if (typeof globalThis !== 'undefined' && globalThis.__env__) {
    return globalThis.__env__
  }
  return {}
}

/**
 * Reads a runtime configuration variable from Cloudflare Worker env/secrets first,
 * falling back to process.env (local dev / Vitest).
 */
export function getRuntimeEnvVar(key: string): string | undefined {
  const cfEnv = getCloudflareEnv()
  const cfVal = cfEnv[key]
  if (typeof cfVal === 'string') {
    return cfVal
  }
  if (typeof process !== 'undefined' && process.env) {
    return process.env[key]
  }
  return undefined
}

export function setActiveWaitUntil(
  waitUntilFn: ((promise: Promise<unknown>) => void) | null,
): void {
  activeWaitUntil = waitUntilFn
}

/**
 * Schedules background work using Cloudflare Workers `ctx.waitUntil` when available,
 * preventing isolates from terminating before async work completes.
 */
export function scheduleBackgroundTask(promise: Promise<unknown>): void {
  const safe = promise.catch((err) => {
    console.error('[pocket365] Background task failed:', err)
  })
  if (activeWaitUntil) {
    try {
      activeWaitUntil(safe)
      return
    } catch {
      // Fall through if waitUntil is no longer active
    }
  }
  void safe
}
