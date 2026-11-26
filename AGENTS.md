# AGENTS.md — Pocket365 Engineering & Architecture Guide

This file documents the architecture, conventions, security invariants, and verification workflow for AI agents and engineers working on **Pocket365** (`pocket365`).

---

## 1. Tech Stack & Runtime
- **Framework:** TanStack Start (`@tanstack/react-start`), TanStack Router (`src/routes/`), TanStack Query, Vite 8, Nitro v3 (`preset: 'node-server'`, output `.output/server/index.mjs`).
- **Language & Runtime:** TypeScript (strict), Node.js 22 LTS.
- **Database:** SQLite via `better-sqlite3` + Drizzle ORM (`src/server/db/`). Stored at `${DATA_DIR}/pocket365.db` (`/data/pocket365.db` in Docker, `./data/pocket365.db` locally). Migrations run automatically on startup via `src/server/db/migrate.ts` (keep matching SQL files in `drizzle/`).
- **Auth:** Microsoft Entra ID OIDC Authorization Code Flow with PKCE (`S256`), single-use `state` + browser cookie binding, `nonce`, and `jose` JWKS signature + `iss`/`aud`/`tid` verification.
- **Styling:** Tailwind CSS v4 (`@tailwindcss/vite`) + `lucide-react`.

---

## 2. Repository Structure
- `src/server.ts` — Custom Nitro server entry: forwarded proxy URL reconstruction (`X-Forwarded-Proto`/`X-Forwarded-Host`), layered rate limiting, CSRF verification, HTTP security headers, and startup initialization of DB + job worker + alert scheduler.
- `src/server/config.ts` — Centralized environment config parser and non-secret `getConfigReadiness()`.
- `src/server/security/` — Defense-in-depth primitives:
  - `rate-limit.ts` — Sliding-window rate limiter (`auth`, `api`, `mutation`, `heavy`).
  - `crypto.ts` — AES-256-GCM authenticated encryption at rest (`enc:v1:...`).
  - `ssrf.ts` — Outbound webhook SSRF blocker (RFC1918, loopback, metadata IPs, DNS resolution check).
  - `headers.ts` — CSRF (`Origin` + `Sec-Fetch-Site`) and HTTP security headers (CSP, HSTS, `X-Frame-Options: DENY`).
  - `csv.ts` — RFC-4180 CSV builder with Excel formula-injection neutralization.
- `src/server/auth/` — OIDC flow (`oidc.ts`), 5-tier granular RBAC (`roles.ts`), SQLite sessions with idle + absolute TTL (`session.ts`), and server guards (`guards.ts`).
- `src/server/db/` — Drizzle schema (`schema.ts`), WAL SQLite singleton (`index.ts`), startup auto-migrator (`migrate.ts`), `audit.ts`, `settings.ts`.
- `src/server/graph/` — App-only Graph token provider (`auth.ts`), Graph v1.0 client with `429 Retry-After` backoff (`client.ts`), SQLite async job runner (`jobs.ts`), AADSTS error diagnosis (`signin-errors.ts`), CIS benchmark evaluator (`cis-benchmarks.ts`, `cis-scanner.ts`), live DNS email auth (`dns-email-auth.ts`), and pure analysis helpers (`mfa-helpers.ts`, `insights-helpers.ts`).
- `src/server/alerts/` — Automated security & drift alert engine (`engine.ts`) with Teams/Slack/Discord/Generic webhooks and 24h deduplication.
- `src/server/billing/` — Commercial tier catalog & server-side `requireEntitlement(...)` (`entitlements.ts`), offline Ed25519-signed license key verification/issuance, and Stripe HMAC-SHA256 webhook verification (`stripe-webhook.ts`).
- `src/server/tenants/` — Multi-tenant MSP registry (`registry.ts`): primary tenant auto-seeding, AES-256-GCM encrypted per-tenant credentials, 1-click Admin Consent onboarding URLs, per-tenant technician access scoping (`tenant_access`), and per-session active tenant context.
- `src/server/functions/` — TanStack Start `createServerFn` RPC endpoints. **Important:** Keep `src/server/functions/*.ts` files exporting *only* `createServerFn` functions (and TypeScript types) so Vite's client build cleanly strips all server/Node imports with zero browser-externalization warnings.
- `src/routes/` — File-based UI pages and raw HTTP API routes (`src/routes/api/`).

---

## 3. Non-Negotiable Security Invariants
1. **Strict Server-Side RBAC:** Every mutating server function and API handler MUST call `requireRole(...)` or `requireCapability(...)` server-side—never rely on hiding UI controls alone.
2. **Audit Every Mutation & Login:** Record an immutable SQLite `audit_logs` entry for logins, RBAC denials, and every mutating Graph/settings/security action.
3. **Never Persist Cleartext Secrets in Logs or Unencrypted Columns:** Never write generated user passwords, Temporary Access Pass (TAP) codes, or BitLocker recovery keys into `audit_logs` or `jobs`. Encrypt stored webhooks and tenant credentials via `encryptSecret()` / `decryptSecret()`.
4. **Reverse Proxy / NPM Compatibility:** Always derive external redirect URLs from `APP_BASE_URL` via `buildCanonicalUrl()`, set `Secure` cookies via `isSecureRequest(request)`, and respect `TRUSTED_PROXY_HOPS` in `getClientIp()`.
5. **Backward Compatibility:** New migrations and env vars must never break existing single-tenant Portainer deployments.

---

## 4. Phase Status
- **Phase 1 (Complete):** Core single-tenant M365 console, Entra OIDC + PKCE, Sign-in Logs, MFA Coverage, 24 CIS Benchmarks + 16 1-click fixes + history, Privileged Roles, Directory Audits, Users/Offboarding/Onboarding, Groups, Mailbox BEC Sweep & Auto-Reply, Apps/OAuth, Stale Cleanup, CA Drift, Devices/BitLocker, Alerts.
- **Phase 2 (Complete):** Layered rate limiting, CSRF & HTTP security headers, AES-256-GCM secret encryption, webhook SSRF protection, CSV formula neutralization, 5-tier granular RBAC (`owner`, `admin`, `helpdesk`, `security_auditor`, `viewer`), active session management UI (`/security`), CI dependency audit.
- **Phase 3 (Complete):** Commercial tiering (`community` / `pro` / `enterprise`), server-side `requireEntitlement(...)` (`402 Payment Required`), offline Ed25519-signed license keys, Stripe HMAC webhook sync (`/api/billing/webhook`), and `/billing` UI.
- **Phase 4 (Complete):** Multi-tenant MSP/SaaS architecture (`managed_tenants`, `tenant_access`, per-session `active_tenant_id`, strictly isolated per-tenant `GraphTokenProvider` & `MicrosoftGraphClient` caches, 1-click Admin Consent onboarding `/api/tenants/consent-callback`, Global Tenant Switcher in `AppShell`, `/tenants` MSP command center, cross-tenant CIS/MFA posture scan, and PostgreSQL Drizzle readiness via `drizzle.pg.config.ts`).

---

## 5. Verification Workflow
Before committing or pushing, always run:
```bash
npm run build && npm run typecheck && npm run lint && npm test
```
Note: `npm run build` must run before `tsc --noEmit` on a fresh checkout so TanStack Start generates `src/routeTree.gen.ts`.
