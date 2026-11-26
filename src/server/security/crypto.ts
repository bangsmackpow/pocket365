import crypto from 'node:crypto'
import { getRuntimeEnvVar } from '~/server/cf/env'
import { getConfig } from '~/server/config'

const V1_PREFIX = 'enc:v1:'
const V2_PREFIX = 'enc:v2:'
const IV_BYTES = 12
const TAG_BYTES = 16

function deriveKeyFromMaterial(rawMaterial: string, salt: string): Buffer {
  const trimmed = rawMaterial.trim()
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex')
  }
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      Buffer.from(trimmed, 'utf8'),
      Buffer.from(salt, 'utf8'),
      Buffer.from('pocket365-aes-256-gcm', 'utf8'),
      32,
    ),
  )
}

function getActiveKeyId(): string {
  const raw = (getRuntimeEnvVar('DATA_ENCRYPTION_KEY_ID') || 'k1')
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, '')
  return raw || 'k1'
}

function derivePrimaryAesKey(): Buffer {
  const cfg = getConfig()
  if (cfg.dataEncryptionKey) {
    return deriveKeyFromMaterial(cfg.dataEncryptionKey, 'pocket365-enc-salt-v1')
  }
  const fallbackMaterial = cfg.sessionSecret || 'pocket365-dev-ephemeral-key'
  return deriveKeyFromMaterial(
    fallbackMaterial,
    'pocket365-session-derived-salt-v1',
  )
}

/**
 * Resolves a key ring mapping `keyId -> 32-byte AES key` supporting zero-downtime
 * rotation via `DATA_ENCRYPTION_PREVIOUS_KEYS="k0:<hex>,k1:<hex>"`.
 */
function buildKeyRing(): { activeKeyId: string; keys: Map<string, Buffer> } {
  const activeKeyId = getActiveKeyId()
  const keys = new Map<string, Buffer>()
  keys.set(activeKeyId, derivePrimaryAesKey())

  const prevRaw = (getRuntimeEnvVar('DATA_ENCRYPTION_PREVIOUS_KEYS') || '').trim()
  if (prevRaw) {
    for (const pair of prevRaw.split(',')) {
      const idx = pair.indexOf(':')
      if (idx <= 0) continue
      const keyId = pair.slice(0, idx).trim()
      const material = pair.slice(idx + 1).trim()
      if (keyId && material && !keys.has(keyId)) {
        keys.set(keyId, deriveKeyFromMaterial(material, 'pocket365-enc-salt-v1'))
      }
    }
  }

  return { activeKeyId, keys }
}

export function isEncryptedValue(value: string): boolean {
  return value.startsWith(V2_PREFIX) || value.startsWith(V1_PREFIX)
}

/**
 * Returns true if a stored secret should be re-encrypted under the current active key
 * (e.g., legacy plaintext, `enc:v1:`, or rotated `enc:v2:<oldKeyId>:`).
 */
export function needsReEncryption(stored: string): boolean {
  if (!stored) return false
  if (!stored.startsWith(V2_PREFIX)) return true
  const body = stored.slice(V2_PREFIX.length)
  const keyId = body.split(':')[0]
  return keyId !== getActiveKeyId()
}

/**
 * Encrypts sensitive database values (webhook URLs, per-tenant credentials, setup secrets)
 * using key-versioned AES-256-GCM authenticated encryption (`enc:v2:<keyId>:...`).
 */
export function encryptSecret(plaintext: string): string {
  if (!plaintext) return ''
  const { activeKeyId, keys } = buildKeyRing()
  const key = keys.get(activeKeyId)!
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ])
  const tag = cipher.getAuthTag()
  return `${V2_PREFIX}${activeKeyId}:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`
}

function decryptAesGcm(
  key: Buffer,
  ivB64: string,
  tagB64: string,
  dataB64: string,
): string {
  const iv = Buffer.from(ivB64, 'base64url')
  const tag = Buffer.from(tagB64, 'base64url')
  const ciphertext = Buffer.from(dataB64, 'base64url')

  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error('Invalid AES-256-GCM IV or authentication tag length.')
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ])
  return plaintext.toString('utf8')
}

/**
 * Decrypts AES-256-GCM values prefixed with `enc:v2:<keyId>:` or legacy `enc:v1:`.
 * Transparently passes through legacy unencrypted strings during upgrade.
 */
export function decryptSecret(stored: string): string {
  if (!stored) return ''

  if (stored.startsWith(V2_PREFIX)) {
    const body = stored.slice(V2_PREFIX.length)
    const parts = body.split(':')
    if (parts.length !== 4) {
      throw new Error('Malformed enc:v2 encrypted payload.')
    }
    const [keyId, ivB64, tagB64, dataB64] = parts as [
      string,
      string,
      string,
      string,
    ]
    const { keys } = buildKeyRing()
    const key = keys.get(keyId)
    if (!key) {
      throw new Error(
        `No decryption key found for keyId "${keyId}". Configure DATA_ENCRYPTION_PREVIOUS_KEYS to complete rotation.`,
      )
    }
    return decryptAesGcm(key, ivB64, tagB64, dataB64)
  }

  if (stored.startsWith(V1_PREFIX)) {
    const body = stored.slice(V1_PREFIX.length)
    const parts = body.split(':')
    if (parts.length !== 3) {
      throw new Error('Malformed encrypted payload.')
    }
    const [ivB64, tagB64, dataB64] = parts as [string, string, string]
    const { keys } = buildKeyRing()
    let lastError: unknown = null
    for (const key of keys.values()) {
      try {
        return decryptAesGcm(key, ivB64, tagB64, dataB64)
      } catch (err) {
        lastError = err
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error('Failed to decrypt enc:v1 payload.')
  }

  return stored
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex')
}
