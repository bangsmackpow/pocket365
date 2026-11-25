import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigCache } from '~/server/config'
import { GraphTokenProvider } from './auth'
import { MicrosoftGraphClient } from './client'
import {
  classifyGraphError,
  decodeJwtRolesClaim,
  diagnoseSignInError,
} from './signin-errors'

describe('Sign-in Logs Troubleshooting & Graph Permissions', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      ENTRA_TENANT_ID: '11111111-2222-3333-4444-555555555555',
      GRAPH_CLIENT_ID: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      GRAPH_CLIENT_SECRET: 'secret',
    }
    resetConfigCache()
  })

  afterEach(() => {
    process.env = { ...originalEnv }
    resetConfigCache()
  })

  it('diagnoses common AADSTS error codes with remediation guidance', () => {
    const success = diagnoseSignInError(0)
    expect(success.category).toBe('success')
    expect(success.aadstsCode).toBe('SUCCESS')

    const badPass = diagnoseSignInError(50126)
    expect(badPass.category).toBe('credentials')
    expect(badPass.aadstsCode).toBe('AADSTS50126')
    expect(badPass.remediation).toMatch(/password/i)

    const secDefaults = diagnoseSignInError(530032)
    expect(secDefaults.category).toBe('conditional_access')
    expect(secDefaults.title).toMatch(/Security Defaults/i)

    const unknown = diagnoseSignInError(999999, 'Custom failure')
    expect(unknown.category).toBe('other')
    expect(unknown.aadstsCode).toBe('AADSTS999999')
    expect(unknown.remediation).toContain('999999')
  })

  it('decodes granted Microsoft Graph application roles from app-only JWT', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64url')
    const payload = Buffer.from(
      JSON.stringify({
        roles: ['User.ReadWrite.All', 'AuditLog.Read.All', 'Group.ReadWrite.All'],
      }),
    ).toString('base64url')
    const fakeJwt = `${header}.${payload}.sig`

    expect(decodeJwtRolesClaim(fakeJwt)).toEqual([
      'AuditLog.Read.All',
      'Group.ReadWrite.All',
      'User.ReadWrite.All',
    ])
  })

  it('classifies permission vs Entra license errors cleanly', () => {
    const permErr = classifyGraphError(
      new Error('Authorization_RequestDenied: Insufficient privileges to complete the operation.'),
      ['AuditLog.Read.All'],
    )
    expect(permErr.kind).toBe('permission')
    expect(permErr.requiredPermissions).toEqual(['AuditLog.Read.All'])

    const licenseErr = classifyGraphError(
      new Error('Neither tenant is B2C or tenant does not have premium license'),
      ['AuditLog.Read.All'],
    )
    expect(licenseErr.kind).toBe('license')
  })

  it('builds correct OData filter queries for listSignInLogs', async () => {
    const tokenFetch = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ access_token: 'a.b.c', expires_in: 3600 }), {
        status: 200,
      }),
    )

    let requestedUrl = ''
    const graphFetch = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      requestedUrl = String(input)
      return new Response(
        JSON.stringify({
          value: [
            {
              id: 's-1',
              createdDateTime: '2026-11-25T20:00:00Z',
              userPrincipalName: 'bob@contoso.com',
              appDisplayName: 'Microsoft Office',
              ipAddress: '203.0.113.10',
              status: { errorCode: 50126, failureReason: 'Invalid password', additionalDetails: null },
            },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    })

    const client = new MicrosoftGraphClient({
      tokenProvider: new GraphTokenProvider(tokenFetch),
      fetchImpl: graphFetch,
    })

    const page = await client.listSignInLogs({
      status: 'failure',
      user: 'bob@contoso.com',
      ipAddress: '203.0.113.10',
      daysBack: 7,
      top: 25,
    })

    expect(page.items).toHaveLength(1)
    const parsed = new URL(requestedUrl)
    expect(parsed.pathname).toBe('/v1.0/auditLogs/signIns')
    const filter = parsed.searchParams.get('$filter') ?? ''
    expect(filter).toContain('status/errorCode ne 0')
    expect(filter).toContain("userPrincipalName eq 'bob@contoso.com'")
    expect(filter).toContain("ipAddress eq '203.0.113.10'")
    expect(filter).toContain('createdDateTime ge ')
  })
})
