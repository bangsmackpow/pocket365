import crypto from 'node:crypto'
import { eq } from 'drizzle-orm'
import {
  getConfig,
  getConfigReadiness,
  type ConfigReadiness,
} from '~/server/config'
import { getDb } from '~/server/db'
import { appSettings } from '~/server/db/schema'
import { GraphTokenProvider } from '~/server/graph/auth'
import { MicrosoftGraphClient } from '~/server/graph/client'
import { POCKET365_GRAPH_PERMISSIONS } from '~/server/graph/signin-errors'
import { decryptSecret, encryptSecret } from '~/server/security/crypto'

export const SETUP_CONFIG_KEY = 'setup.entra_config'

interface StoredEntraSetupPayload {
  entraTenantId: string
  oidcClientId: string
  oidcClientSecretEnc: string
  graphClientId: string
  graphClientSecretEnc?: string | null
  graphCertThumbprint?: string | null
  graphCertPrivateKeyEnc?: string | null
  ownerEntries: string[]
  adminEntries: string[]
  configuredBy: string
  configuredAt: number
}

export interface EffectiveEntraConfig {
  source: 'env' | 'd1_setup' | 'unconfigured'
  entraTenantId: string
  oidcClientId: string
  oidcClientSecret: string
  graphClientId: string
  graphClientSecret: string
  graphCertThumbprint: string
  graphCertPrivateKey: string
  ownerEntries: string[]
  adminEntries: string[]
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8')
  const bufB = Buffer.from(b, 'utf8')
  if (bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

export function verifySetupBootstrapToken(providedToken?: string): boolean {
  const cfg = getConfig()
  if (!cfg.setupBootstrapToken) {
    return true
  }
  if (!providedToken) return false
  return constantTimeEquals(providedToken.trim(), cfg.setupBootstrapToken)
}

export async function getStoredEntraSetup(): Promise<StoredEntraSetupPayload | null> {
  try {
    const db = getDb()
    const row = await db
      .select()
      .from(appSettings)
      .where(eq(appSettings.key, SETUP_CONFIG_KEY))
      .get()
    if (!row) return null
    return JSON.parse(row.valueJson) as StoredEntraSetupPayload
  } catch {
    return null
  }
}

/**
 * Resolves effective Entra OIDC & Graph configuration.
 * Cloudflare Worker Secrets / env vars take precedence; otherwise falls back to
 * AES-256-GCM encrypted credentials saved via the self-hosted `/setup` wizard in D1.
 */
export async function getEffectiveEntraConfig(): Promise<EffectiveEntraConfig> {
  const cfg = getConfig()
  const envOidcReady =
    cfg.deploymentMode === 'saas'
      ? Boolean(cfg.oidcClientId && cfg.oidcClientSecret)
      : Boolean(cfg.entraTenantId && cfg.oidcClientId && cfg.oidcClientSecret)

  if (envOidcReady) {
    return {
      source: 'env',
      entraTenantId: cfg.entraTenantId,
      oidcClientId: cfg.oidcClientId,
      oidcClientSecret: cfg.oidcClientSecret,
      graphClientId: cfg.graphClientId,
      graphClientSecret: cfg.graphClientSecret,
      graphCertThumbprint: cfg.graphCertThumbprint,
      graphCertPrivateKey: cfg.graphCertPrivateKey,
      ownerEntries: cfg.ownerEntries,
      adminEntries: cfg.adminEntries,
    }
  }

  const stored = await getStoredEntraSetup()
  if (stored && stored.entraTenantId && stored.oidcClientId && stored.oidcClientSecretEnc) {
    return {
      source: 'd1_setup',
      entraTenantId: stored.entraTenantId,
      oidcClientId: stored.oidcClientId,
      oidcClientSecret: decryptSecret(stored.oidcClientSecretEnc),
      graphClientId: stored.graphClientId || stored.oidcClientId,
      graphClientSecret: stored.graphClientSecretEnc
        ? decryptSecret(stored.graphClientSecretEnc)
        : '',
      graphCertThumbprint: stored.graphCertThumbprint || '',
      graphCertPrivateKey: stored.graphCertPrivateKeyEnc
        ? decryptSecret(stored.graphCertPrivateKeyEnc)
        : '',
      ownerEntries: stored.ownerEntries ?? [],
      adminEntries: stored.adminEntries ?? [],
    }
  }

  return {
    source: 'unconfigured',
    entraTenantId: cfg.entraTenantId,
    oidcClientId: cfg.oidcClientId,
    oidcClientSecret: cfg.oidcClientSecret,
    graphClientId: cfg.graphClientId,
    graphClientSecret: cfg.graphClientSecret,
    graphCertThumbprint: cfg.graphCertThumbprint,
    graphCertPrivateKey: cfg.graphCertPrivateKey,
    ownerEntries: cfg.ownerEntries,
    adminEntries: cfg.adminEntries,
  }
}

export async function isInitialSetupRequired(): Promise<boolean> {
  const cfg = getConfig()
  if (cfg.deploymentMode === 'saas') return false
  const effective = await getEffectiveEntraConfig()
  return effective.source === 'unconfigured'
}

/**
 * Returns full instance readiness combining Cloudflare Worker secrets/env vars
 * with AES-256-GCM encrypted credentials persisted via the self-hosted `/setup` wizard.
 */
export async function getEffectiveConfigReadiness(): Promise<ConfigReadiness> {
  const base = getConfigReadiness()
  const effective = await getEffectiveEntraConfig()

  const hasCertAuth = Boolean(
    effective.graphClientId &&
      effective.graphCertThumbprint &&
      effective.graphCertPrivateKey,
  )
  const hasSecretAuth = Boolean(
    effective.graphClientId && effective.graphClientSecret,
  )

  return {
    ...base,
    singleTenantConfigured:
      base.singleTenantConfigured || Boolean(effective.entraTenantId),
    oidcConfigured:
      base.oidcConfigured ||
      Boolean(
        effective.entraTenantId &&
          effective.oidcClientId &&
          effective.oidcClientSecret,
      ),
    graphConfigured:
      base.graphConfigured ||
      Boolean(effective.entraTenantId && (hasCertAuth || hasSecretAuth)),
    graphAuthMode: hasCertAuth
      ? 'certificate'
      : hasSecretAuth
        ? 'client_secret'
        : base.graphAuthMode,
    rbacConfigured:
      base.rbacConfigured ||
      effective.ownerEntries.length > 0 ||
      effective.adminEntries.length > 0,
  }
}

export async function saveEntraSetupConfig(params: {
  entraTenantId: string
  oidcClientId: string
  oidcClientSecret: string
  graphClientId?: string
  graphClientSecret?: string
  graphCertThumbprint?: string
  graphCertPrivateKey?: string
  ownerEntries: string[]
  adminEntries?: string[]
  updatedBy: string
}): Promise<void> {
  const db = getDb()
  const now = Date.now()
  const payload: StoredEntraSetupPayload = {
    entraTenantId: params.entraTenantId.trim(),
    oidcClientId: params.oidcClientId.trim(),
    oidcClientSecretEnc: encryptSecret(params.oidcClientSecret.trim()),
    graphClientId: (params.graphClientId || params.oidcClientId).trim(),
    graphClientSecretEnc: params.graphClientSecret?.trim()
      ? encryptSecret(params.graphClientSecret.trim())
      : null,
    graphCertThumbprint: params.graphCertThumbprint
      ? params.graphCertThumbprint.trim().replace(/[:\s]/g, '')
      : null,
    graphCertPrivateKeyEnc: params.graphCertPrivateKey?.trim()
      ? encryptSecret(params.graphCertPrivateKey.trim().replace(/\\n/g, '\n'))
      : null,
    ownerEntries: params.ownerEntries
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    adminEntries: (params.adminEntries ?? [])
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    configuredBy: params.updatedBy,
    configuredAt: now,
  }

  await db
    .insert(appSettings)
    .values({
      key: SETUP_CONFIG_KEY,
      valueJson: JSON.stringify(payload),
      updatedBy: params.updatedBy,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: appSettings.key,
      set: {
        valueJson: JSON.stringify(payload),
        updatedBy: params.updatedBy,
        updatedAt: now,
      },
    })
    .run()
}

export async function testEntraGraphSetup(params: {
  entraTenantId: string
  graphClientId: string
  graphClientSecret?: string
  graphCertThumbprint?: string
  graphCertPrivateKey?: string
}): Promise<{
  ok: boolean
  organizationName: string | null
  primaryDomain: string | null
  grantedRoles: string[]
  missingCoreRoles: string[]
  error?: string
}> {
  try {
    const provider = new GraphTokenProvider(fetch, {
      entraTenantId: params.entraTenantId.trim(),
      clientId: params.graphClientId.trim(),
      clientSecret: params.graphClientSecret?.trim() || undefined,
      certThumbprint: params.graphCertThumbprint?.trim() || undefined,
      certPrivateKey: params.graphCertPrivateKey?.trim() || undefined,
    })
    const client = new MicrosoftGraphClient({
      tokenProvider: provider,
      maxRetries: 1,
    })

    const [org, grantedRoles] = await Promise.all([
      client.getOrganization(),
      client.getGrantedRoles().catch(() => [] as string[]),
    ])

    const grantedSet = new Set(grantedRoles.map((r) => r.toLowerCase()))
    const coreRequired = ['User.ReadWrite.All', 'Organization.Read.All', 'AuditLog.Read.All']
    const missingCoreRoles = coreRequired.filter(
      (r) => !grantedSet.has(r.toLowerCase()),
    )

    const primaryDomain =
      org?.verifiedDomains.find((d) => d.isDefault)?.name ??
      org?.verifiedDomains[0]?.name ??
      null

    return {
      ok: true,
      organizationName: org?.displayName ?? null,
      primaryDomain,
      grantedRoles,
      missingCoreRoles,
    }
  } catch (err) {
    return {
      ok: false,
      organizationName: null,
      primaryDomain: null,
      grantedRoles: [],
      missingCoreRoles: [],
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

/**
 * Generates a 1-click PowerShell (Microsoft.Graph) script that creates the Pocket365
 * Entra App Registration, assigns required Graph permissions, creates a secret, and
 * outputs a single JSON payload ready to paste into the /setup wizard.
 */
export function generatePowerShellBootstrapScript(appBaseUrl: string): string {
  const base = appBaseUrl.replace(/\/+$/, '')
  const redirectUri = `${base}/api/auth/callback`
  const permList = POCKET365_GRAPH_PERMISSIONS.map((p) => `'${p.permission}'`).join(', ')

  return `# Pocket365 1-Click Entra ID App Bootstrap Script
# Run in PowerShell (Windows PowerShell 5.1+, PowerShell 7+, or Azure Cloud Shell)
# Sign in as Global Administrator or Application Administrator when prompted

& {
  $ErrorActionPreference = "Stop"

  # 0. Ensure lightweight Microsoft Graph modules are installed (skip full 40-module suite)
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
  $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

  if ($missingModules) {
    Write-Host "Installing required PowerShell modules: $($missingModules -join ', ')..." -ForegroundColor Cyan
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    foreach ($mod in $missingModules) {
      Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
  }

  Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications

  Write-Host "Signing in to Microsoft Graph..." -ForegroundColor Cyan
  Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Directory.Read.All"

  $ctx = Get-MgContext
  if (-not $ctx -or -not $ctx.TenantId) {
    throw "Microsoft Graph sign-in did not complete. Please run the script again and complete the browser prompt."
  }

  $tenantId = $ctx.TenantId
  $redirectUri = "${redirectUri}"

  # 1. Create Single-Tenant Entra App Registration
  Write-Host "Creating Entra ID App Registration (Pocket365 Self-Hosted)..." -ForegroundColor Cyan
  $app = New-MgApplication -DisplayName "Pocket365 Self-Hosted" \`
    -SignInAudience "AzureADMyOrg" \`
    -Web @{ RedirectUris = @($redirectUri) } \`
    -GroupMembershipClaims "SecurityGroup"

  $sp = New-MgServicePrincipal -AppId $app.AppId
  Write-Host "Waiting 5 seconds for Entra ID service principal replication..." -ForegroundColor Cyan
  Start-Sleep -Seconds 5

  # 2. Resolve & Assign Microsoft Graph Application Permissions (Grants Admin Consent)
  Write-Host "Granting Microsoft Graph permissions..." -ForegroundColor Cyan
  $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
  $desiredPermissions = @(${permList})
  $resourceAccess = @()

  foreach ($permName in $desiredPermissions) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName -and $_.AllowedMemberTypes -contains "Application" } | Select-Object -First 1
    if ($role) {
      $resourceAccess += @{ Id = $role.Id; Type = "Role" }
      try {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id \`
          -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
      } catch {
        Write-Warning "Could not assign $($permName): $($_.Exception.Message)"
      }
    }
  }

  Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @(
    @{ ResourceAppId = "00000003-0000-0000-c000-000000000000"; ResourceAccess = $resourceAccess }
  )

  # 3. Create 24-Month Client Secret
  Write-Host "Creating 24-month client secret..." -ForegroundColor Cyan
  $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "Pocket365-Worker-Secret"
    EndDateTime = (Get-Date).AddYears(2)
  }

  # 4. Output Setup JSON (Paste directly into Pocket365 /setup)
  $setupBlob = [ordered]@{
    entraTenantId     = $tenantId
    oidcClientId      = $app.AppId
    oidcClientSecret  = $secret.SecretText
    graphClientId     = $app.AppId
    graphClientSecret = $secret.SecretText
    ownerUpn          = $ctx.Account
  } | ConvertTo-Json -Compress

  Write-Host ""
  Write-Host "=== COPY THIS JSON INTO POCKET365 /setup ===" -ForegroundColor Green
  Write-Host $setupBlob
  Write-Host "============================================" -ForegroundColor Green
}
`
}
