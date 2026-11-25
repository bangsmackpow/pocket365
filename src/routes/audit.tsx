import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  Activity,
  Clock,
  RefreshCw,
  RotateCcw,
  Search,
} from 'lucide-react'
import { useState } from 'react'
import {
  listAuditLogsFn,
  listJobsFn,
  retryJobFn,
} from '~/server/functions/audit'

export const Route = createFileRoute('/audit')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'Audit & Jobs — Pocket365' }],
  }),
  component: AuditAndJobsPage,
})

function AuditAndJobsPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin'
  const queryClient = useQueryClient()

  const [tab, setTab] = useState<'audit' | 'jobs'>('audit')
  const [auditStatus, setAuditStatus] = useState<
    'all' | 'success' | 'failure' | 'queued'
  >('all')
  const [auditSearch, setAuditSearch] = useState('')
  const [jobStatus, setJobStatus] = useState<
    'all' | 'queued' | 'running' | 'completed' | 'failed'
  >('all')

  const auditQuery = useQuery({
    queryKey: ['audit-logs', auditStatus, auditSearch],
    queryFn: () =>
      listAuditLogsFn({
        data: {
          status: auditStatus,
          search: auditSearch || undefined,
          limit: 150,
        },
      }),
  })

  const jobsQuery = useQuery({
    queryKey: ['jobs', jobStatus],
    queryFn: () =>
      listJobsFn({
        data: {
          status: jobStatus,
          limit: 100,
        },
      }),
    refetchInterval: (query) => {
      const hasActive = query.state.data?.jobs.some(
        (j) => j.status === 'queued' || j.status === 'running',
      )
      return hasActive ? 3000 : false
    },
  })

  const retryMutation = useMutation({
    mutationFn: (jobId: string) => retryJobFn({ data: { jobId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] })
    },
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Audit Log & Background Jobs
          </h1>
          <p className="text-sm text-slate-600">
            Immutable SQLite record of authentication events, Graph mutations,
            and async bulk operations.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            auditQuery.refetch()
            jobsQuery.refetch()
          }}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 cursor-pointer"
        >
          <RefreshCw
            className={`h-4 w-4 ${
              auditQuery.isFetching || jobsQuery.isFetching ? 'animate-spin' : ''
            }`}
          />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 flex gap-6">
        <button
          type="button"
          onClick={() => setTab('audit')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer transition-colors ${
            tab === 'audit'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Activity className="h-4 w-4" />
          Audit Log ({auditQuery.data?.logs.length ?? 0})
        </button>
        <button
          type="button"
          onClick={() => setTab('jobs')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer transition-colors ${
            tab === 'jobs'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Clock className="h-4 w-4" />
          Background Jobs ({jobsQuery.data?.jobs.length ?? 0})
        </button>
      </div>

      {tab === 'audit' ? (
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3 shadow-xs">
            <div className="relative flex-1 min-w-60">
              <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={auditSearch}
                onChange={(e) => setAuditSearch(e.target.value)}
                placeholder="Filter by actor UPN, action, or target..."
                className="w-full pl-9 pr-3 py-2 text-sm border border-slate-300 rounded-lg"
              />
            </div>
            <select
              value={auditStatus}
              onChange={(e) =>
                setAuditStatus(
                  e.target.value as 'all' | 'success' | 'failure' | 'queued',
                )
              }
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
            >
              <option value="all">All statuses</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="queued">Queued</option>
            </select>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                  <tr>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Actor</th>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3">Target</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {(auditQuery.data?.logs ?? []).length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-8 text-center text-slate-500"
                      >
                        No audit events match your filters.
                      </td>
                    </tr>
                  ) : (
                    auditQuery.data!.logs.map((log) => (
                      <tr key={log.id} className="hover:bg-slate-50/70">
                        <td className="px-4 py-3 whitespace-nowrap text-slate-600">
                          {new Date(log.createdAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-slate-900">
                            {log.actorUpn}
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            {log.actorRole} • {log.actorOid.slice(0, 12)}
                          </div>
                        </td>
                        <td className="px-4 py-3 font-mono text-slate-800">
                          {log.action}
                        </td>
                        <td className="px-4 py-3 text-slate-700 max-w-xs truncate">
                          {log.target}
                        </td>
                        <td className="px-4 py-3">
                          <Pill status={log.status} />
                        </td>
                        <td className="px-4 py-3">
                          <details>
                            <summary className="cursor-pointer text-indigo-600 font-medium">
                              Inspect
                            </summary>
                            <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-100 text-[11px] max-w-md overflow-x-auto">
                              {formatJson(log.detailsJson)}
                            </pre>
                          </details>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-white rounded-xl border border-slate-200 p-4 flex items-center justify-between gap-3 shadow-xs">
            <span className="text-xs text-slate-600">
              Bulk user and group operations run asynchronously via SQLite so
              requests never time out.
            </span>
            <select
              value={jobStatus}
              onChange={(e) =>
                setJobStatus(
                  e.target.value as
                    | 'all'
                    | 'queued'
                    | 'running'
                    | 'completed'
                    | 'failed',
                )
              }
              className="px-3 py-2 text-sm border border-slate-300 rounded-lg bg-white"
            >
              <option value="all">All statuses</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-50 text-xs uppercase text-slate-500 border-b border-slate-200">
                  <tr>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3">Job Type</th>
                    <th className="px-4 py-3">Actor</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Attempts</th>
                    <th className="px-4 py-3">Output</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {(jobsQuery.data?.jobs ?? []).length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-8 text-center text-slate-500"
                      >
                        No background jobs queued yet.
                      </td>
                    </tr>
                  ) : (
                    jobsQuery.data!.jobs.map((job) => (
                      <tr key={job.id} className="hover:bg-slate-50/70">
                        <td className="px-4 py-3 whitespace-nowrap text-slate-600">
                          {new Date(job.createdAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-mono font-medium text-slate-900">
                            {job.type}
                          </div>
                          <div className="text-[11px] font-mono text-slate-400">
                            {job.id}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-700">
                          {job.actorUpn}
                        </td>
                        <td className="px-4 py-3">
                          <Pill status={job.status} />
                        </td>
                        <td className="px-4 py-3 text-slate-600">
                          {job.attempts} / {job.maxAttempts}
                        </td>
                        <td className="px-4 py-3 space-y-1">
                          {job.error && (
                            <div className="text-rose-700 font-medium">
                              {job.error}
                            </div>
                          )}
                          <details>
                            <summary className="cursor-pointer text-indigo-600 font-medium">
                              Payload & Result
                            </summary>
                            <pre className="mt-1 p-2 rounded bg-slate-900 text-slate-100 text-[11px] max-w-md overflow-x-auto">
                              {formatJson(
                                JSON.stringify({
                                  payload: safeParse(job.payloadJson),
                                  result: job.resultJson
                                    ? safeParse(job.resultJson)
                                    : null,
                                }),
                              )}
                            </pre>
                          </details>
                          {isAdmin && job.status === 'failed' && (
                            <button
                              type="button"
                              disabled={retryMutation.isPending}
                              onClick={() => retryMutation.mutate(job.id)}
                              className="mt-1 inline-flex items-center gap-1 px-2 py-1 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 hover:bg-indigo-100 cursor-pointer"
                            >
                              <RotateCcw className="h-3 w-3" />
                              Retry
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Pill({ status }: { status: string }) {
  const styles =
    status === 'success' || status === 'completed'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
      : status === 'failure' || status === 'failed'
        ? 'bg-rose-50 text-rose-700 border-rose-200'
        : status === 'running'
          ? 'bg-sky-50 text-sky-700 border-sky-200'
          : 'bg-amber-50 text-amber-700 border-amber-200'
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${styles}`}
    >
      {status}
    </span>
  )
}

function safeParse(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

function formatJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
