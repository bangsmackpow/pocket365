import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resetConfigCache } from '~/server/config'
import { closeTestDb, initDbForTesting } from '~/server/db/test-d1'
import { getCanonicalBaseUrl } from '~/server/http/proxy'
import {
  decryptSecret,
  encryptSecret,
  isEncryptedValue,
  needsReEncryption,
} from '~/server/security/crypto'
import {
  generatePowerShellBootstrapScript,
  getEffectiveEntraConfig,
  isInitialSetupRequired,
  saveEntraSetupConfig,
  verifySetupBootstrapToken,
} from './service'

describe('Phase CF-3 Self-Hosted /setup Wizard & Key-Versioned enc:v2 Rotation', () => {
  const originalEnv = { ...process.env }
  const KEY_V1 = '1111111111111111111111111111111111111111111111111111111111111111'
  const KEY_V2 = '2222222222222222222222222222222222222222222222222222222222222222'

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      DEPLOYMENT_MODE: 'self_hosted',
      APP_BASE_URL: 'https://m365.contoso.workers.dev',
      SESSION_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
      DATA_ENCRYPTION_KEY: KEY_V1,
      DATA_ENCRYPTION_KEY_ID: 'k1',
      SETUP_BOOTSTRAP_TOKEN: 'bootstrap-secret-xyz',
      ENTRA_TENANT_ID: '',
      OIDC_CLIENT_ID: '',
      OIDC_CLIENT_SECRET: '',
      GRAPH_CLIENT_ID: '',
      GRAPH_CLIENT_SECRET: '',
    }
    resetConfigCache()
    initDbForTesting()
  })

  afterEach(() => {
    closeTestDb()
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('encrypts with key-versioned enc:v2 and supports zero-downtime key rotation', () => {
    const cipherV1 = encryptSecret('super-secret-entra-key')
    expect(cipherV1.startsWith('enc:v2:k1:')).toBe(true)
    expect(isEncryptedValue(cipherV1)).toBe(true)
    expect(needsReEncryption(cipherV1)).toBe(false)
    expect(decryptSecret(cipherV1)).toBe('super-secret-entra-key')

    // Rotate active key to k2 while keeping k1 in DATA_ENCRYPTION_PREVIOUS_KEYS
    process.env.DATA_ENCRYPTION_KEY = KEY_V2
    process.env.DATA_ENCRYPTION_KEY_ID = 'k2'
    process.env.DATA_ENCRYPTION_PREVIOUS_KEYS = `k1:${KEY_V1}`

    expect(needsReEncryption(cipherV1)).toBe(true)
    expect(decryptSecret(cipherV1)).toBe('super-secret-entra-key')

    const reEncrypted = encryptSecret(decryptSecret(cipherV1))
    expect(reEncrypted.startsWith('enc:v2:k2:')).toBe(true)
    expect(needsReEncryption(reEncrypted)).toBe(false)
    expect(decryptSecret(reEncrypted)).toBe('super-secret-entra-key')
  })

  it('verifies setup bootstrap token, saves encrypted Entra config in D1, and locks setup', async () => {
    expect(await isInitialSetupRequired()).toBe(true)
    expect(verifySetupBootstrapToken('wrong-token')).toBe(false)
    expect(verifySetupBootstrapToken('bootstrap-secret-xyz')).toBe(true)

    await saveEntraSetupConfig({
      entraTenantId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      oidcClientId: '11111111-2222-3333-4444-555555555555',
      oidcClientSecret: 'oidc-secret-value-1234',
      graphClientId: '11111111-2222-3333-4444-555555555555',
      graphClientSecret: 'graph-secret-value-5678',
      ownerEntries: ['Founder@Contoso.com'],
      updatedBy: 'setup:wizard',
    })

    expect(await isInitialSetupRequired()).toBe(false)

    const effective = await getEffectiveEntraConfig()
    expect(effective.source).toBe('d1_setup')
    expect(effective.entraTenantId).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    expect(effective.oidcClientSecret).toBe('oidc-secret-value-1234')
    expect(effective.graphClientSecret).toBe('graph-secret-value-5678')
    expect(effective.ownerEntries).toEqual(['founder@contoso.com'])
  })

  it('generates a ready-to-run PowerShell Entra bootstrap script with canonical callback URL', () => {
    const script = generatePowerShellBootstrapScript(
      'https://m365.contoso.workers.dev/',
    )
    expect(script).toContain('& {')
    expect(script).toContain('Microsoft.Graph.Authentication')
    expect(script).toContain('Microsoft.Graph.Applications')
    expect(script).toContain('Connect-MgGraph')
    expect(script).toContain('https://m365.contoso.workers.dev/api/auth/callback')
    expect(script).toContain('User.ReadWrite.All')
    expect(script).toContain('ConvertTo-Json -Compress')
  })

  it('automatically detects live custom HTTPS domain from incoming request over fallback APP_BASE_URL', () => {
    const customReq = new Request('https://pocket365.builtbyvets.app/setup')
    expect(getCanonicalBaseUrl(customReq)).toBe(
      'https://pocket365.builtbyvets.app',
    )

    const script = generatePowerShellBootstrapScript(
      getCanonicalBaseUrl(customReq),
    )
    expect(script).toContain(
      'https://pocket365.builtbyvets.app/api/auth/callback',
    )

    // Without a request (e.g. cron/background), falls back to APP_BASE_URL
    expect(getCanonicalBaseUrl()).toBe('https://m365.contoso.workers.dev')
  })
})
