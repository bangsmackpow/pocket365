import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import {
  CheckCircle2,
  Layers,
  Plus,
  Trash2,
  UserPlus,
  XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import {
  deleteOnboardingTemplateFn,
  getOnboardingDataFn,
  onboardNewUserFn,
  saveOnboardingTemplateFn,
  type ClientOnboardingTemplate,
} from '~/server/functions/onboarding'

export const Route = createFileRoute('/onboarding')({
  beforeLoad: ({ context, location }) => {
    if (!context.auth.user) {
      throw redirect({
        to: '/login',
        search: { returnTo: location.pathname },
      })
    }
  },
  head: () => ({
    meta: [{ title: 'User Onboarding — Pocket365' }],
  }),
  component: OnboardingPage,
})

function OnboardingPage() {
  const { auth } = Route.useRouteContext()
  const isAdmin = auth.user?.role === 'admin' || auth.user?.role === 'owner'
  const queryClient = useQueryClient()

  const [tab, setTab] = useState<'wizard' | 'templates'>('wizard')
  const [banner, setBanner] = useState<{
    type: 'success' | 'error'
    text: string
  } | null>(null)

  // Wizard state
  const [selectedTemplateId, setSelectedTemplateId] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [givenName, setGivenName] = useState('')
  const [surname, setSurname] = useState('')
  const [mailNickname, setMailNickname] = useState('')
  const [domain, setDomain] = useState('')
  const [department, setDepartment] = useState('')
  const [jobTitle, setJobTitle] = useState('')
  const [officeLocation, setOfficeLocation] = useState('')
  const [usageLocation, setUsageLocation] = useState('US')
  const [skuIds, setSkuIds] = useState<string[]>([])
  const [groupIds, setGroupIds] = useState<string[]>([])
  const [issueTap, setIssueTap] = useState(false)
  const [forcePasswordChange, setForcePasswordChange] = useState(true)

  const [handoff, setHandoff] = useState<{
    upn: string
    password: string
    tap: string | null
    steps: Array<{ step: string; ok: boolean; error?: string }>
  } | null>(null)

  // Template editor state
  const [tplName, setTplName] = useState('')
  const [tplDesc, setTplDesc] = useState('')
  const [tplDept, setTplDept] = useState('')
  const [tplTitle, setTplTitle] = useState('')
  const [tplOffice, setTplOffice] = useState('')
  const [tplUsage, setTplUsage] = useState('US')
  const [tplSkuIds, setTplSkuIds] = useState<string[]>([])
  const [tplGroupIds, setTplGroupIds] = useState<string[]>([])
  const [tplTap, setTplTap] = useState(false)

  const query = useQuery({
    queryKey: ['onboarding-data'],
    queryFn: () => getOnboardingDataFn(),
  })

  useEffect(() => {
    if (!domain && query.data?.verifiedDomains.length) {
      const def =
        query.data.verifiedDomains.find((d) => d.isDefault) ??
        query.data.verifiedDomains[0]
      if (def) setDomain(def.id)
    }
  }, [domain, query.data?.verifiedDomains])

  const applyTemplate = (tpl: ClientOnboardingTemplate) => {
    setSelectedTemplateId(tpl.id)
    setDepartment(tpl.department)
    setJobTitle(tpl.jobTitle)
    setOfficeLocation(tpl.officeLocation)
    setUsageLocation(tpl.usageLocation)
    setSkuIds(tpl.skuIds)
    setGroupIds(tpl.groupIds)
    setIssueTap(tpl.issueTap)
    setForcePasswordChange(tpl.forcePasswordChange)
  }

  const onboardMutation = useMutation({
    mutationFn: () =>
      onboardNewUserFn({
        data: {
          displayName,
          givenName,
          surname,
          mailNickname,
          domain,
          department,
          jobTitle,
          officeLocation,
          usageLocation,
          skuIds,
          groupIds,
          issueTap,
          forcePasswordChange,
        },
      }),
    onSuccess: (res) => {
      setHandoff({
        upn: res.userPrincipalName,
        password: res.temporaryPassword,
        tap: res.temporaryAccessPass,
        steps: res.steps,
      })
      setDisplayName('')
      setGivenName('')
      setSurname('')
      setMailNickname('')
      setBanner({
        type: 'success',
        text: `Provisioned ${res.userPrincipalName} cleanly.`,
      })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Onboarding failed.',
      })
    },
  })

  const saveTemplateMutation = useMutation({
    mutationFn: () =>
      saveOnboardingTemplateFn({
        data: {
          name: tplName,
          description: tplDesc,
          department: tplDept,
          jobTitle: tplTitle,
          officeLocation: tplOffice,
          usageLocation: tplUsage,
          skuIds: tplSkuIds,
          groupIds: tplGroupIds,
          issueTap: tplTap,
          forcePasswordChange: true,
        },
      }),
    onSuccess: () => {
      setTplName('')
      setTplDesc('')
      setTplDept('')
      setTplTitle('')
      setTplOffice('')
      setTplSkuIds([])
      setTplGroupIds([])
      setTplTap(false)
      setBanner({ type: 'success', text: 'Onboarding template saved.' })
      queryClient.invalidateQueries({ queryKey: ['onboarding-data'] })
    },
    onError: (err) => {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save template.',
      })
    },
  })

  const deleteTemplateMutation = useMutation({
    mutationFn: (id: string) => deleteOnboardingTemplateFn({ data: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['onboarding-data'] })
    },
  })

  const toggleArr = (arr: string[], id: string) =>
    arr.includes(id) ? arr.filter((x) => x !== id) : [...arr, id]

  const skus = query.data?.subscribedSkus ?? []
  const groups = query.data?.groups ?? []
  const templates = query.data?.templates ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          User Onboarding & Role Templates
        </h1>
        <p className="text-sm text-slate-600">
          Provision new Microsoft 365 users consistently with reusable SQLite
          role templates (licenses, groups, department, strong password, and
          optional Temporary Access Pass).
        </p>
      </div>

      {banner && (
        <div
          className={`rounded-xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          <span>{banner.text}</span>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {handoff && (
        <div className="rounded-xl bg-indigo-50 border border-indigo-200 p-5 text-xs text-indigo-950 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm font-bold">
              New Hire Provisioned — One-Time Credentials
            </div>
            <button
              type="button"
              onClick={() => setHandoff(null)}
              className="underline cursor-pointer"
            >
              Clear credentials
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-white rounded-lg border border-indigo-200 p-3">
              <div className="text-[11px] text-slate-500">UPN / Email</div>
              <div className="font-mono font-bold select-all mt-0.5">
                {handoff.upn}
              </div>
            </div>
            <div className="bg-white rounded-lg border border-indigo-200 p-3">
              <div className="text-[11px] text-slate-500">
                Temporary Password (shown once)
              </div>
              <div className="font-mono font-bold select-all mt-0.5">
                {handoff.password}
              </div>
            </div>
            {handoff.tap && (
              <div className="bg-white rounded-lg border border-indigo-200 p-3">
                <div className="text-[11px] text-slate-500">
                  Temporary Access Pass (60m)
                </div>
                <div className="font-mono font-bold select-all mt-0.5">
                  {handoff.tap}
                </div>
              </div>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {handoff.steps.map((s, i) => (
              <span
                key={i}
                title={s.error}
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-medium ${
                  s.ok
                    ? 'bg-emerald-100 text-emerald-800'
                    : 'bg-rose-100 text-rose-800'
                }`}
              >
                {s.ok ? (
                  <CheckCircle2 className="h-3 w-3" />
                ) : (
                  <XCircle className="h-3 w-3" />
                )}
                {s.step}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-slate-200 flex gap-6">
        <button
          type="button"
          onClick={() => setTab('wizard')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer ${
            tab === 'wizard'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <UserPlus className="h-4 w-4" />
          Onboard New User
        </button>
        <button
          type="button"
          onClick={() => setTab('templates')}
          className={`pb-3 text-sm font-medium border-b-2 inline-flex items-center gap-2 cursor-pointer ${
            tab === 'templates'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Layers className="h-4 w-4" />
          Role Templates ({templates.length})
        </button>
      </div>

      {!isAdmin && (
        <div className="rounded-xl bg-sky-50 border border-sky-200 p-4 text-xs text-sky-900">
          You are in a read-only session. Creating users and managing onboarding
          templates require <code className="font-mono">admin</code> privileges.
        </div>
      )}

      {tab === 'wizard' ? (
        <form
          className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-5 text-xs"
          onSubmit={(e) => {
            e.preventDefault()
            onboardMutation.mutate()
          }}
        >
          {templates.length > 0 && (
            <div className="space-y-1.5">
              <div className="font-semibold text-slate-700">
                Apply Role Template (Optional)
              </div>
              <div className="flex flex-wrap gap-2">
                {templates.map((tpl) => (
                  <button
                    key={tpl.id}
                    type="button"
                    onClick={() => applyTemplate(tpl)}
                    className={`px-3 py-1.5 rounded-lg border font-medium cursor-pointer ${
                      selectedTemplateId === tpl.id
                        ? 'bg-indigo-600 text-white border-indigo-600'
                        : 'bg-slate-50 text-slate-700 border-slate-300 hover:bg-slate-100'
                    }`}
                  >
                    {tpl.name} ({tpl.skuIds.length} lic, {tpl.groupIds.length}{' '}
                    grp)
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Display Name *</span>
              <input
                type="text"
                required
                disabled={!isAdmin}
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">First Name</span>
              <input
                type="text"
                disabled={!isAdmin}
                value={givenName}
                onChange={(e) => setGivenName(e.target.value)}
                placeholder="Jane"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Last Name</span>
              <input
                type="text"
                disabled={!isAdmin}
                value={surname}
                onChange={(e) => setSurname(e.target.value)}
                placeholder="Doe"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Username *</span>
              <input
                type="text"
                required
                disabled={!isAdmin}
                value={mailNickname}
                onChange={(e) => setMailNickname(e.target.value)}
                placeholder="jdoe"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg font-mono"
              />
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Domain *</span>
              <select
                required
                disabled={!isAdmin}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg bg-white"
              >
                {(query.data?.verifiedDomains ?? []).map((d) => (
                  <option key={d.id} value={d.id}>
                    @{d.id}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">
                Usage Location (2-letter ISO)
              </span>
              <input
                type="text"
                maxLength={2}
                disabled={!isAdmin}
                value={usageLocation}
                onChange={(e) => setUsageLocation(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg uppercase font-mono"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Department</span>
              <input
                type="text"
                disabled={!isAdmin}
                value={department}
                onChange={(e) => setDepartment(e.target.value)}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Job Title</span>
              <input
                type="text"
                disabled={!isAdmin}
                value={jobTitle}
                onChange={(e) => setJobTitle(e.target.value)}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
            <label className="space-y-1 block">
              <span className="font-medium text-slate-700">Office Location</span>
              <input
                type="text"
                disabled={!isAdmin}
                value={officeLocation}
                onChange={(e) => setOfficeLocation(e.target.value)}
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-100">
            <div className="space-y-2">
              <div className="font-semibold text-slate-700">
                Assign Licenses ({skuIds.length})
              </div>
              <div className="border border-slate-200 rounded-lg p-3 max-h-44 overflow-y-auto space-y-1.5">
                {skus.map((s) => (
                  <label
                    key={s.skuId}
                    className="flex items-center justify-between gap-2 cursor-pointer"
                  >
                    <span className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        disabled={!isAdmin}
                        checked={skuIds.includes(s.skuId)}
                        onChange={() => setSkuIds(toggleArr(skuIds, s.skuId))}
                      />
                      <span className="font-mono">{s.skuPartNumber}</span>
                    </span>
                    <span className="text-slate-400">
                      {Math.max(0, s.prepaidUnits.enabled - s.consumedUnits)}{' '}
                      avail
                    </span>
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <div className="font-semibold text-slate-700">
                Add to Groups ({groupIds.length})
              </div>
              <div className="border border-slate-200 rounded-lg p-3 max-h-44 overflow-y-auto space-y-1.5">
                {groups.map((g) => (
                  <label
                    key={g.id}
                    className="flex items-center gap-2 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      disabled={!isAdmin}
                      checked={groupIds.includes(g.id)}
                      onChange={() => setGroupIds(toggleArr(groupIds, g.id))}
                    />
                    <span className="truncate">{g.displayName}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-6 pt-2">
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                disabled={!isAdmin}
                checked={forcePasswordChange}
                onChange={(e) => setForcePasswordChange(e.target.checked)}
              />
              <span>Require password change at first sign-in</span>
            </label>
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                disabled={!isAdmin}
                checked={issueTap}
                onChange={(e) => setIssueTap(e.target.checked)}
              />
              <span>Also generate 60-minute Temporary Access Pass (TAP)</span>
            </label>
          </div>

          {isAdmin && (
            <button
              type="submit"
              disabled={onboardMutation.isPending}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50 cursor-pointer"
            >
              <UserPlus className="h-4 w-4" />
              {onboardMutation.isPending
                ? 'Provisioning User...'
                : 'Create & Provision User'}
            </button>
          )}
        </form>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Saved Templates */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 font-semibold text-sm text-slate-900">
              Saved Role Templates
            </div>
            {templates.length === 0 ? (
              <div className="p-6 text-xs text-slate-500">
                No onboarding templates saved yet.
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {templates.map((tpl) => (
                  <div
                    key={tpl.id}
                    className="p-4 text-xs flex items-start justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="font-semibold text-slate-900">
                        {tpl.name}
                      </div>
                      {tpl.description && (
                        <div className="text-slate-600">{tpl.description}</div>
                      )}
                      <div className="text-slate-500">
                        Dept: {tpl.department || '—'} • Title:{' '}
                        {tpl.jobTitle || '—'} • Loc: {tpl.usageLocation}
                      </div>
                      <div className="text-slate-500">
                        {tpl.skuIds.length} license(s) • {tpl.groupIds.length}{' '}
                        group(s) • TAP: {tpl.issueTap ? 'Yes' : 'No'}
                      </div>
                    </div>
                    {isAdmin && (
                      <button
                        type="button"
                        onClick={() => deleteTemplateMutation.mutate(tpl.id)}
                        className="p-1.5 rounded text-rose-600 hover:bg-rose-50 cursor-pointer"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* New Template Form */}
          {isAdmin && (
            <form
              className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4 text-xs"
              onSubmit={(e) => {
                e.preventDefault()
                saveTemplateMutation.mutate()
              }}
            >
              <div className="font-semibold text-sm text-slate-900">
                Create Onboarding Template
              </div>
              <input
                type="text"
                required
                value={tplName}
                onChange={(e) => setTplName(e.target.value)}
                placeholder="Template name (e.g. Standard Staff)"
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
              <input
                type="text"
                value={tplDesc}
                onChange={(e) => setTplDesc(e.target.value)}
                placeholder="Short description..."
                className="w-full px-3 py-2 border border-slate-300 rounded-lg"
              />
              <div className="grid grid-cols-2 gap-3">
                <input
                  type="text"
                  value={tplDept}
                  onChange={(e) => setTplDept(e.target.value)}
                  placeholder="Default department"
                  className="px-3 py-2 border border-slate-300 rounded-lg"
                />
                <input
                  type="text"
                  value={tplTitle}
                  onChange={(e) => setTplTitle(e.target.value)}
                  placeholder="Default job title"
                  className="px-3 py-2 border border-slate-300 rounded-lg"
                />
                <input
                  type="text"
                  value={tplOffice}
                  onChange={(e) => setTplOffice(e.target.value)}
                  placeholder="Default office"
                  className="px-3 py-2 border border-slate-300 rounded-lg"
                />
                <input
                  type="text"
                  maxLength={2}
                  value={tplUsage}
                  onChange={(e) => setTplUsage(e.target.value.toUpperCase())}
                  placeholder="US"
                  className="px-3 py-2 border border-slate-300 rounded-lg uppercase font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <div className="font-medium text-slate-700">
                  Preset Licenses
                </div>
                <div className="border border-slate-200 rounded-lg p-2.5 max-h-32 overflow-y-auto space-y-1">
                  {skus.map((s) => (
                    <label
                      key={s.skuId}
                      className="flex items-center gap-2 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={tplSkuIds.includes(s.skuId)}
                        onChange={() =>
                          setTplSkuIds(toggleArr(tplSkuIds, s.skuId))
                        }
                      />
                      <span className="font-mono">{s.skuPartNumber}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="font-medium text-slate-700">Preset Groups</div>
                <div className="border border-slate-200 rounded-lg p-2.5 max-h-32 overflow-y-auto space-y-1">
                  {groups.map((g) => (
                    <label
                      key={g.id}
                      className="flex items-center gap-2 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={tplGroupIds.includes(g.id)}
                        onChange={() =>
                          setTplGroupIds(toggleArr(tplGroupIds, g.id))
                        }
                      />
                      <span className="truncate">{g.displayName}</span>
                    </label>
                  ))}
                </div>
              </div>

              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={tplTap}
                  onChange={(e) => setTplTap(e.target.checked)}
                />
                <span>Issue Temporary Access Pass by default</span>
              </label>

              <button
                type="submit"
                disabled={saveTemplateMutation.isPending}
                className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
              >
                <Plus className="h-3.5 w-3.5" />
                Save Template
              </button>
            </form>
          )}
        </div>
      )}
    </div>
  )
}
