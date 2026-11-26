import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'
import { z } from 'zod'
import { requireRole, requireSession } from '~/server/auth/guards'
import { listAuditLogs } from '~/server/db/audit'
import { listJobs, retryFailedJob } from '~/server/graph/jobs'
import { getClientIp } from '~/server/http/proxy'

const listAuditInputSchema = z.object({
  limit: z.number().int().min(1).max(500).optional(),
  status: z.enum(['all', 'success', 'failure', 'queued']).optional(),
  search: z.string().max(120).optional(),
})

export const listAuditLogsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listAuditInputSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    const session = await requireSession()
    return {
      logs: await listAuditLogs({
        organizationId: session.organizationId,
        limit: data.limit ?? 100,
        status: data.status ?? 'all',
        search: data.search,
      }),
    }
  })

const listJobsInputSchema = z.object({
  limit: z.number().int().min(1).max(200).optional(),
  status: z.enum(['all', 'queued', 'running', 'completed', 'failed']).optional(),
})

export const listJobsFn = createServerFn({ method: 'GET' })
  .validator((input: unknown) => listJobsInputSchema.parse(input ?? {}))
  .handler(async ({ data }) => {
    const session = await requireSession()
    return {
      jobs: await listJobs({
        organizationId: session.organizationId,
        limit: data.limit ?? 50,
        status: data.status ?? 'all',
      }),
    }
  })

const retryJobInputSchema = z.object({
  jobId: z.string().uuid(),
})

export const retryJobFn = createServerFn({ method: 'POST' })
  .validator((input: unknown) => retryJobInputSchema.parse(input))
  .handler(async ({ data }) => {
    const session = await requireRole('admin', undefined, 'job.retry')
    const job = await retryFailedJob(
      data.jobId,
      { oid: session.oid, upn: session.upn, role: session.role },
      getClientIp(getRequest()),
    )
    return { job }
  })
