import crypto from 'node:crypto'
import { getConfig } from '~/server/config'

const ENCRYPTED_PREFIX = 'enc:v1:'
const IV_BYTES = 12
const TAG_BYTES = 16

function deriveAesKey(): Buffer {
  const cfg = getConfig()
  const explicit = cfg.dataEncryptionKey
  if (explicit) {
    if (/^[0-9a-fA-F]{64}$/.test(explicit)) {
      return Buffer.from(explicit, 'hex')
    }
    return Buffer.from(
      crypto.hkdfSync(
        'sha256',
        Buffer.from(explicit, 'utf8'),
        Buffer.from('pocket365-enc-salt-v1', 'utf8'),
        Buffer.from('pocket365-aes-256-gcm', 'utf8'),
        32,
      ),
    )
  }

  const fallbackMaterial = cfg.sessionSecret || 'pocket365-dev-ephemeral-key'
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      Buffer.from(fallbackMaterial, 'utf8'),
      Buffer.from('pocket365-session-derived-salt-v1', 'utf8'),
      Buffer.from('pocket365-aes-256-gcm', 'utf8'),
      32,
    ),
  )
}

export function isEncryptedValue(value: string): boolean {
  return value.startsWith(ENCRYPTED_PREFIX)
}

/**
 * Encrypts sensitive database values (webhook URLs, per-tenant credentials)
 * using AES-256-GCM authenticated encryption.
 */
export function encryptSecret(plaintext: string): string {
  if (!plaintext) return ''
  const key = deriveAesKey()
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ])
  const tag = cipher.getAuthTag()
  return `${ENCRYPTED_PREFIX}${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`
}

/**
 * Decrypts AES-256-GCM values prefixed with `enc:v1:`.
 * Transparently passes through legacy unencrypted strings during upgrade.
 */
export function decryptSecret(stored: string): string {
  if (!stored) return ''
  if (!isEncryptedValue(stored)) {
    return stored
  }

  const body = stored.slice(ENCRYPTED_PREFIX.length)
  const parts = body.split(':')
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted payload.')
  }

  const [ivB64, tagB64, dataB64] = parts as [string, string, string]
  const iv = Buffer.from(ivB64, 'base64url')
  const tag = Buffer.from(tagB64, 'base64url')
  const ciphertext = Buffer.from(dataB64, 'base64url')

  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error('Invalid AES-256-GCM IV or authentication tag length.')
  }

  const key = deriveAesKey()
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ])
  return plaintext.toString('utf8')
}

export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex')
}
