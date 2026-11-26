import { runScheduledAlertSweep } from '~/server/alerts/engine'
import { type CloudflareEnv, type Pocket365QueueMessage } from './env'
import { drainQueuedJobs, processJobById } from '~/server/graph/jobs'

/**
 * Executed on Cloudflare Cron Triggers (`triggers.crons` in wrangler.jsonc).
 * Drains pending async jobs and runs the automated security/drift alert sweep.
 */
export async function handleCloudflareScheduled(_params: {
  controller?: ScheduledController
  env?: CloudflareEnv
}): Promise<{ jobsProcessed: number; alertsTriggered: number }> {
  let jobsProcessed = 0
  let alertsTriggered = 0

  try {
    jobsProcessed = await drainQueuedJobs(10)
  } catch (err) {
    console.error('[pocket365] Scheduled job drain error:', err)
  }

  try {
    const summary = await runScheduledAlertSweep()
    alertsTriggered = summary?.alertsTriggered ?? 0
  } catch (err) {
    console.error('[pocket365] Scheduled alert sweep error:', err)
  }

  return { jobsProcessed, alertsTriggered }
}

/**
 * Executed by Cloudflare Queues consumer when `POCKET365_QUEUE` is configured
 * (Workers Paid plan / SaaS mode).
 */
export async function handleCloudflareQueue(
  batch: MessageBatch<Pocket365QueueMessage>,
): Promise<void> {
  for (const msg of batch.messages) {
    try {
      if (msg.body?.kind === 'job' && typeof msg.body.jobId === 'string') {
        await processJobById(msg.body.jobId)
      }
      msg.ack()
    } catch (err) {
      console.error('[pocket365] Queue message processing error:', err)
      msg.retry()
    }
  }
}
