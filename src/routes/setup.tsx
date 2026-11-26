import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import {
  CheckCircle2,
  Clipboard,
  ClipboardCheck,
  KeyRound,
  Lock,
  ShieldCheck,
  Terminal,
  Wrench,
} from 'lucide-react'
import { useState } from 'react'
import {
  getSetupWizardStateFn,
  saveSetupConfigFn,
  testSetupConnectionFn,
  unlockSetupWizardFn,
} from '~/server/functions/setup'

export const Route = createFileRoute('/setup')({
  head: () => ({
    meta: [{ title: 'First-Run Setup — Pocket365' }],
  }),
  component: SetupWizardPage,
})

function SetupWizardPage() {
  const stateQuery = useQuery({
    queryKey: ['setup', 'state'],
    queryFn: () => getSetupWizardStateFn(),
  })

  const [bootstrapToken, setBootstrapToken] = useState('')
  const [unlockedScript, setUnlockedScript] = useState<string | null>(null)
  const [jsonBlob, setJsonBlob] = useState('')
  const [entraTenantId, setEntraTenantId] = useState('')
  const [oidcClientId, setOidcClientId] = useState('')
  const [oidcClientSecret, setOidcClientSecret] = useState('')
  const [graphClientId, setGraphClientId] = useState('')
  const [graphClientSecret, setGraphClientSecret] = useState('')
  const [graphCertThumbprint, setGraphCertThumbprint] = useState('')
  const [graphCertPrivateKey, setGraphCertPrivateKey] = useState('')
  const [authMode, setAuthMode] = useState<'client_secret' | 'certificate'>(
    'client_secret',
  )
  const [ownerEntries, setOwnerEntries] = useState('')
  const [adminEntries, setAdminEntries] = useState('')
  const [copied, setCopied] = useState(false)
  const [blobMsg, setBlobMsg] = useState<string | null>(null)
  const [savedOk, setSavedOk] = useState(false)

  const unlockMutation = useMutation({
    mutationFn: () => unlockSetupWizardFn({ data: { bootstrapToken } }),
    onSuccess: (res) => {
      setUnlockedScript(res.powershellScript)
    },
  })

  const testMutation = useMutation({
    mutationFn: () =>
      testSetupConnectionFn({
        data: {
          bootstrapToken: bootstrapToken || undefined,
          entraTenantId,
          graphClientId: graphClientId || oidcClientId,
          graphClientSecret:
            authMode === 'client_secret'
              ? graphClientSecret || oidcClientSecret
              : undefined,
          graphCertThumbprint:
            authMode === 'certificate' ? graphCertThumbprint : undefined,
          graphCertPrivateKey:
            authMode === 'certificate' ? graphCertPrivateKey : undefined,
        },
      }),
  })

  const saveMutation = useMutation({
    mutationFn: () =>
      saveSetupConfigFn({
        data: {
          bootstrapToken: bootstrapToken || undefined,
          entraTenantId,
          oidcClientId,
          oidcClientSecret,
          graphClientId: graphClientId || oidcClientId,
          graphClientSecret:
            authMode === 'client_secret'
              ? graphClientSecret || oidcClientSecret
              : undefined,
          graphCertThumbprint:
            authMode === 'certificate' ? graphCertThumbprint : undefined,
          graphCertPrivateKey:
            authMode === 'certificate' ? graphCertPrivateKey : undefined,
          ownerEntries,
          adminEntries: adminEntries || undefined,
        },
      }),
    onSuccess: () => {
      setSavedOk(true)
      void stateQuery.refetch()
    },
  })

  const applyJsonBlob = () => {
    try {
      const parsed = JSON.parse(jsonBlob.trim()) as Record<string, unknown>
      if (typeof parsed.entraTenantId === 'string')
        setEntraTenantId(parsed.entraTenantId)
      if (typeof parsed.oidcClientId === 'string')
        setOidcClientId(parsed.oidcClientId)
      if (typeof parsed.oidcClientSecret === 'string')
        setOidcClientSecret(parsed.oidcClientSecret)
      if (typeof parsed.graphClientId === 'string')
        setGraphClientId(parsed.graphClientId)
      if (typeof parsed.graphClientSecret === 'string')
        setGraphClientSecret(parsed.graphClientSecret)
      if (typeof parsed.ownerUpn === 'string' && !ownerEntries)
        setOwnerEntries(parsed.ownerUpn)
      setBlobMsg('Applied PowerShell bootstrap JSON to the form below.')
    } catch {
      setBlobMsg('Could not parse JSON. Paste the single-line JSON output from PowerShell.')
    }
  }

  const effectiveScript = unlockedScript ?? stateQuery.data?.powershellScript ?? ''

  const copyScript = async () => {
    if (!effectiveScript) return
    await navigator.clipboard.writeText(effectiveScript)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const data = stateQuery.data

  if (stateQuery.isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-300 text-sm">
        Loading Pocket365 setup wizard...
      </div>
    )
  }

  if (data?.locked) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-xl border border-slate-200 p-8 space-y-4 text-center">
          <div className="h-12 w-12 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center mx-auto">
            <Lock className="h-6 w-6" />
          </div>
          <h1 className="text-xl font-bold text-slate-900">
            Pocket365 Is Already Configured
          </h1>
          <p className="text-sm text-slate-600">
            First-run setup is locked for security. Sign in as an{' '}
            <span className="font-semibold">owner</span> to update Entra
            credentials, or update Cloudflare Worker secrets directly.
          </p>
          <Link
            to="/login"
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold"
          >
            Go to Sign In
          </Link>
        </div>
      </div>
    )
  }

  if (data?.requiresBootstrapToken && !unlockedScript) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-xl border border-slate-200 p-8 space-y-5">
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0">
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-900">
                Unlock First-Run Setup
              </h1>
              <p className="text-xs text-slate-500">
                Protected by your Cloudflare Worker{' '}
                <code>SETUP_BOOTSTRAP_TOKEN</code> secret
              </p>
            </div>
          </div>

          <p className="text-xs text-slate-600 leading-relaxed">
            Enter your deployment&apos;s bootstrap token to reveal the initial
            configuration wizard. Once setup completes, this endpoint locks
            automatically.
          </p>

          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (bootstrapToken.trim()) {
                unlockMutation.mutate()
              }
            }}
          >
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Setup Bootstrap Token
              </label>
              <input
                type="password"
                value={bootstrapToken}
                onChange={(e) => setBootstrapToken(e.target.value)}
                placeholder="Paste SETUP_BOOTSTRAP_TOKEN"
                autoComplete="off"
                className="w-full px-3 py-2.5 rounded-lg border border-slate-300 text-sm font-mono"
              />
            </div>

            {unlockMutation.error && (
              <div className="rounded-lg p-3 bg-rose-50 border border-rose-200 text-xs text-rose-800">
                {unlockMutation.error instanceof Error
                  ? unlockMutation.error.message
                  : String(unlockMutation.error)}
              </div>
            )}

            <button
              type="submit"
              disabled={unlockMutation.isPending || !bootstrapToken.trim()}
              className="w-full px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold"
            >
              {unlockMutation.isPending ? 'Verifying...' : 'Unlock Setup Wizard'}
            </button>
          </form>

          <div className="pt-2 border-t border-slate-100 text-center">
            <Link
              to="/login"
              className="text-xs text-slate-500 hover:text-slate-700 underline"
            >
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 py-10 px-4">
      <div className="max-w-3xl mx-auto space-y-6">
        {/* Header */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-white flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-xl bg-indigo-600 flex items-center justify-center">
              <Wrench className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">
                Pocket365 Self-Hosted Setup Wizard
              </h1>
              <p className="text-xs text-slate-400">
                Encrypted in Cloudflare D1 (`enc:v2` AES-256-GCM) — zero `.env`
                file editing required
              </p>
            </div>
          </div>
          <Link
            to="/login"
            className="text-xs text-indigo-300 hover:text-indigo-200 underline"
          >
            Back to Sign In
          </Link>
        </div>

        {savedOk && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-5 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 text-emerald-900">
              <CheckCircle2 className="h-6 w-6 text-emerald-600 shrink-0" />
              <div>
                <div className="font-semibold text-sm">
                  Entra ID Configuration Saved & Encrypted!
                </div>
                <div className="text-xs text-emerald-800">
                  Setup is now locked. Sign in with your Microsoft account to
                  enter Pocket365.
                </div>
              </div>
            </div>
            <a
              href="/api/auth/login"
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shrink-0"
            >
              Sign in with Microsoft →
            </a>
          </div>
        )}

        {/* Step 1: 1-Click PowerShell Bootstrap */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-indigo-600" />
              <h2 className="text-base font-semibold text-slate-900">
                Step 1 — 1-Click Entra App Registration (PowerShell)
              </h2>
            </div>
            <button
              type="button"
              onClick={copyScript}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium"
            >
              {copied ? (
                <>
                  <ClipboardCheck className="h-3.5 w-3.5 text-emerald-400" />
                  Copied!
                </>
              ) : (
                <>
                  <Clipboard className="h-3.5 w-3.5" />
                  Copy Script
                </>
              )}
            </button>
          </div>

          <p className="text-xs text-slate-600">
            Run this script as a Microsoft 365 Global Admin or Application Admin.
            It registers Pocket365 with Redirect URI{' '}
            <code className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-800">
              {data?.callbackUrl}
            </code>
            , assigns the required Microsoft Graph permissions, and prints a
            single JSON line to paste below.
          </p>

          <pre className="bg-slate-950 text-slate-200 text-[11px] p-4 rounded-xl overflow-x-auto max-h-52 font-mono">
            {effectiveScript}
          </pre>

          <div className="flex gap-2">
            <input
              type="text"
              value={jsonBlob}
              onChange={(e) => setJsonBlob(e.target.value)}
              placeholder='Paste JSON output from PowerShell here ({"entraTenantId":...})'
              className="flex-1 px-3 py-2 rounded-lg border border-slate-300 text-xs font-mono"
            />
            <button
              type="button"
              onClick={applyJsonBlob}
              className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold"
            >
              Auto-Fill Form
            </button>
          </div>
          {blobMsg && <p className="text-xs text-indigo-700">{blobMsg}</p>}
        </div>

        {/* Step 2: Credentials Form */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-indigo-600" />
            <h2 className="text-base font-semibold text-slate-900">
              Step 2 — Entra ID & Owner RBAC Configuration
            </h2>
          </div>

          {data?.requiresBootstrapToken && (
            <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 space-y-1.5">
              <label className="block text-xs font-semibold text-amber-900">
                Setup Bootstrap Token (required by SETUP_BOOTSTRAP_TOKEN secret)
              </label>
              <input
                type="password"
                value={bootstrapToken}
                onChange={(e) => setBootstrapToken(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-amber-300 bg-white text-sm"
                placeholder="Enter SETUP_BOOTSTRAP_TOKEN"
              />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Directory (Tenant) ID *
              </label>
              <input
                type="text"
                value={entraTenantId}
                onChange={(e) => setEntraTenantId(e.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Application (Client) ID *
              </label>
              <input
                type="text"
                value={oidcClientId}
                onChange={(e) => setOidcClientId(e.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                OIDC Client Secret *
              </label>
              <input
                type="password"
                value={oidcClientSecret}
                onChange={(e) => setOidcClientSecret(e.target.value)}
                placeholder="Entra App Client Secret value"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
              />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-700">
                Microsoft Graph App-Only Auth Mode
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setAuthMode('client_secret')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium ${
                    authMode === 'client_secret'
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-100 text-slate-700'
                  }`}
                >
                  Client Secret
                </button>
                <button
                  type="button"
                  onClick={() => setAuthMode('certificate')}
                  className={`px-3 py-1 rounded-lg text-xs font-medium ${
                    authMode === 'certificate'
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-100 text-slate-700'
                  }`}
                >
                  X.509 Certificate (Recommended)
                </button>
              </div>
            </div>

            {authMode === 'client_secret' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">
                    Graph Client ID (defaults to OIDC Client ID)
                  </label>
                  <input
                    type="text"
                    value={graphClientId}
                    onChange={(e) => setGraphClientId(e.target.value)}
                    placeholder="Optional if same App Registration"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">
                    Graph Client Secret (defaults to OIDC Secret)
                  </label>
                  <input
                    type="password"
                    value={graphClientSecret}
                    onChange={(e) => setGraphClientSecret(e.target.value)}
                    placeholder="Optional if same App Registration"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">
                    Certificate SHA-1 Thumbprint (40 hex chars)
                  </label>
                  <input
                    type="text"
                    value={graphCertThumbprint}
                    onChange={(e) => setGraphCertThumbprint(e.target.value)}
                    placeholder="0123456789ABCDEF..."
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-600 mb-1">
                    PKCS#8 Private Key (PEM)
                  </label>
                  <textarea
                    rows={4}
                    value={graphCertPrivateKey}
                    onChange={(e) => setGraphCertPrivateKey(e.target.value)}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-xs font-mono"
                  />
                </div>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-slate-100 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Owner UPN(s) or Group OIDs *
              </label>
              <input
                type="text"
                value={ownerEntries}
                onChange={(e) => setOwnerEntries(e.target.value)}
                placeholder="admin@yourdomain.com"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 mb-1">
                Additional Admin UPN(s) / Groups (optional)
              </label>
              <input
                type="text"
                value={adminEntries}
                onChange={(e) => setAdminEntries(e.target.value)}
                placeholder="it-admin@yourdomain.com"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
              />
            </div>
          </div>

          {/* Step 3: Live Test & Save */}
          <div className="pt-4 border-t border-slate-100 flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={testMutation.isPending || !entraTenantId || !oidcClientId}
              onClick={() => testMutation.mutate()}
              className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-sm font-semibold"
            >
              {testMutation.isPending
                ? 'Testing Graph Connection...'
                : 'Test Graph Connection'}
            </button>
            <button
              type="button"
              disabled={
                saveMutation.isPending ||
                !entraTenantId ||
                !oidcClientId ||
                !oidcClientSecret ||
                !ownerEntries
              }
              onClick={() => saveMutation.mutate()}
              className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold inline-flex items-center gap-2"
            >
              <ShieldCheck className="h-4 w-4" />
              {saveMutation.isPending
                ? 'Encrypting & Saving...'
                : 'Save & Lock Setup'}
            </button>
          </div>

          {testMutation.data && (
            <div
              className={`rounded-xl p-4 text-xs space-y-1 border ${
                testMutation.data.ok
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  : 'bg-rose-50 border-rose-200 text-rose-900'
              }`}
            >
              {testMutation.data.ok ? (
                <>
                  <div className="font-semibold">
                    Connected to {testMutation.data.organizationName || 'Entra Tenant'}{' '}
                    ({testMutation.data.primaryDomain || entraTenantId})
                  </div>
                  <div>
                    Granted Graph App Permissions:{' '}
                    <span className="font-mono">
                      {testMutation.data.grantedRoles.length}
                    </span>
                    {testMutation.data.missingCoreRoles.length > 0 && (
                      <span className="text-amber-700 ml-2">
                        Missing core: {testMutation.data.missingCoreRoles.join(', ')}
                      </span>
                    )}
                  </div>
                </>
              ) : (
                <div className="font-semibold">
                  Connection failed: {testMutation.data.error}
                </div>
              )}
            </div>
          )}

          {saveMutation.error && (
            <div className="rounded-xl p-3 bg-rose-50 border border-rose-200 text-xs text-rose-800">
              {saveMutation.error instanceof Error
                ? saveMutation.error.message
                : String(saveMutation.error)}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
