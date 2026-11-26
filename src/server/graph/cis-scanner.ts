import {
  evaluateCisBenchmarks,
  summarizeCisChecks,
  type CisTenantSnapshot,
} from './cis-benchmarks'
import { getGraphClient } from './client'
import { auditDomainEmailAuth } from './dns-email-auth'

export async function collectCisScan(managedTenantId?: string) {
  const graph = await getGraphClient(managedTenantId)

  const snapshot: CisTenantSnapshot = {
    authorizationPolicy: null,
    securityDefaults: null,
    adminConsentPolicy: null,
    conditionalAccessEnabledCount: null,
    directoryRoles: null,
    mfaRegistrations: null,
    domains: null,
    emailAuthAudits: null,
    sharePointSettings: null,
    authMethodsPolicy: null,
  }

  await Promise.all([
    graph
      .getAuthorizationPolicy()
      .then((p) => {
        snapshot.authorizationPolicy = p
      })
      .catch((err) => {
        snapshot.authorizationPolicyError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .getSecurityDefaultsPolicy()
      .then((p) => {
        snapshot.securityDefaults = p
      })
      .catch((err) => {
        snapshot.securityDefaultsError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .getAdminConsentRequestPolicy()
      .then((p) => {
        snapshot.adminConsentPolicy = p
      })
      .catch((err) => {
        snapshot.adminConsentPolicyError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .listConditionalAccessPoliciesSummary()
      .then((policies) => {
        snapshot.conditionalAccessEnabledCount = policies.filter(
          (p) => p.state === 'enabled',
        ).length
      })
      .catch(() => {
        snapshot.conditionalAccessEnabledCount = 0
      }),
    graph
      .listDirectoryRolesWithMembers()
      .then((roles) => {
        snapshot.directoryRoles = roles
      })
      .catch((err) => {
        snapshot.directoryRolesError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .listUserRegistrationDetails({ top: 500 })
      .then((res) => {
        snapshot.mfaRegistrations = res.items
      })
      .catch((err) => {
        snapshot.mfaRegistrationsError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .listDomains()
      .then(async (domains) => {
        snapshot.domains = domains
        const customVerified = domains
          .filter(
            (d) =>
              d.isVerified &&
              !d.id.toLowerCase().endsWith('.onmicrosoft.com'),
          )
          .slice(0, 10)
        if (customVerified.length > 0) {
          snapshot.emailAuthAudits = await Promise.all(
            customVerified.map((d) => auditDomainEmailAuth(d.id)),
          )
        }
      })
      .catch((err) => {
        snapshot.domainsError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .getSharePointSettings()
      .then((sp) => {
        snapshot.sharePointSettings = sp
      })
      .catch((err) => {
        snapshot.sharePointSettingsError =
          err instanceof Error ? err.message : String(err)
      }),
    graph
      .getAuthenticationMethodsPolicy()
      .then((amp) => {
        snapshot.authMethodsPolicy = amp
      })
      .catch((err) => {
        snapshot.authMethodsPolicyError =
          err instanceof Error ? err.message : String(err)
      }),
  ])

  const checks = evaluateCisBenchmarks(snapshot)
  const summary = summarizeCisChecks(checks)

  return {
    scannedAt: new Date().toISOString(),
    checks,
    summary,
  }
}
