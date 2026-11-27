# AGENTS.md — Pocket365 Engineering & Architecture Guide

This file documents the architecture, conventions, security invariants, and verification workflow for AI agents and engineers working on **Pocket365** (`pocket365`).

---

## 1. Tech Stack & Runtime
- **Platform:** 100% **Cloudflare Full Stack** — Cloudflare Workers (`nitro` preset `'cloudflare-module'` + `nodejs_compat`), configured in `wrangler.jsonc`.
- **Framework:** TanStack Start (`@tanstack/react-start`), TanStack Router (`src/routes/`), TanStack Query, Vite 8, Nitro v3.
- **Language & Runtime:** TypeScript (strict), Cloudflare Workers (`workerd` + `nodejs_compat`), Node.js 22 LTS for builds/tests.
- **Database:** Cloudflare **D1** (SQLite at the edge) via Drizzle ORM (`drizzle-orm/d1`). SQL migrations live in `drizzle/` (applied via `wrangler d1 migrations apply pocket365-db --remote`) and mirror `src/server/db/migrate.ts`. Unit tests use Node 22's built-in `node:sqlite` wrapped in a spec-compliant `D1Database` shim (`src/server/db/test-d1.ts`) with zero native npm dependencies.
- **Edge Storage & Jobs:**
  - **Cloudflare KV** (`POCKET365_KV`): Distributed sliding-window rate limits + encrypted short-lived Graph OAuth token cache (`src/server/cf/kv.ts`).
  - **Cloudflare R2** (`POCKET365_R2`): Archived CIS compliance reports and audit exports (`src/server/cf/r2.ts`, `/api/exports/download`).
  - **Cloudflare Cron Triggers & Queues** (`src/server/cf/handlers.ts`): Automated alert sweeps and async job drainage via Nitro `cloudflare:scheduled` and `cloudflare:queue` hooks (with automatic `ctx.waitUntil()` fallback when `POCKET365_QUEUE` is unbound for CF Free plan compatibility).
- **Auth:** Microsoft Entra ID OIDC Authorization Code Flow with PKCE (`S256`), single-use `state` + browser cookie binding, `nonce`, and `jose` JWKS signature + `iss`/`aud`/`tid` verification.
- **DNS Resolution:** Pure-fetch **DNS-over-HTTPS** (`https://cloudflare-dns.com/dns-query` in `src/server/security/doh.ts`) for CIS SPF/DKIM/DMARC checks and webhook SSRF checks (zero `node:dns` / `node:net` usage).
- **Styling:** Tailwind CSS v4 (`@tailwindcss/vite`) + `lucide-react`.

---

## 2. Repository Structure
- `wrangler.jsonc` — Cloudflare Worker configuration (D1 `DB`, KV `POCKET365_KV`, R2 `POCKET365_R2`, Cron Triggers `*/15 * * * *`, `nodejs_compat`, `DEPLOYMENT_MODE`).
- `src/server.ts` — Custom Nitro/Workers server entry: `waitUntil` binding, forwarded URL handling, KV-backed layered rate limiting, CSRF verification, HTTP security headers, and Nitro `cloudflare:scheduled` / `cloudflare:queue` hook registration.
- `src/server/cf/` — Cloudflare platform bindings (`env.ts`), KV wrapper (`kv.ts`), R2 export storage (`r2.ts`), and Cron/Queue handlers (`handlers.ts`).
- `src/server/config.ts` — Live runtime config parser reading Cloudflare Worker env/secrets (`globalThis.__env__`) with `process.env` fallback.
- `src/server/security/` — Defense-in-depth primitives:
  - `rate-limit.ts` — KV-backed distributed + memory fallback sliding-window rate limiter (`auth`, `api`, `mutation`, `heavy`).
  - `crypto.ts` — AES-256-GCM authenticated encryption at rest (`enc:v1:...`).
  - `doh.ts` & `ssrf.ts` — DNS-over-HTTPS resolver and outbound webhook SSRF blocker (RFC1918, loopback, metadata IPs, pure-JS IPv4/IPv6 checks).
  - `headers.ts` — CSRF (`Origin` + `Sec-Fetch-Site`) and HTTP security headers (CSP, HSTS, `X-Frame-Options: DENY`).
  - `csv.ts` — RFC-4180 CSV builder with Excel formula-injection neutralization.
- `src/server/auth/` — OIDC flow (`oidc.ts`), 5-tier granular RBAC (`roles.ts`), D1 sessions with idle + absolute TTL (`session.ts`), and async server guards (`guards.ts`).
- `src/server/db/` — Drizzle schema (`schema.ts`), async D1 singleton (`index.ts`), migration SQL definitions (`migrate.ts`), Node 22 `node:sqlite` D1 test shim (`test-d1.ts`), `audit.ts`, `settings.ts`.
- `src/server/graph/` — App-only Graph token provider with KV caching (`auth.ts`), Graph v1.0 client with `429 Retry-After` backoff (`client.ts`), D1 + Queue/waitUntil async job runner (`jobs.ts`), AADSTS error diagnosis (`signin-errors.ts`), CIS benchmark evaluator (`cis-benchmarks.ts`, `cis-scanner.ts`), DoH email auth (`dns-email-auth.ts`), pure analysis helpers (`mfa-helpers.ts`, `insights-helpers.ts`), and structured diagnostic logging (`[Pocket365 Graph Auth]`).
- `src/server/alerts/` — Automated security & drift alert engine (`engine.ts`) triggered via Cloudflare Cron Triggers (`runScheduledAlertSweep`), with Teams/Slack/Discord/Generic webhooks and 24h deduplication.
- `src/server/billing/` — Commercial tier catalog & server-side `requireEntitlement(...)` (`entitlements.ts`), offline Ed25519-signed license key verification/issuance, and Stripe HMAC-SHA256 webhook verification (`stripe-webhook.ts`).
- `src/server/tenants/` — Multi-tenant MSP registry (`registry.ts`): primary tenant auto-seeding & D1 auto-healing, AES-256-GCM encrypted per-tenant credentials, fallback credential resolution chain (`resolveTenantGraphCredentials`), 1-click Admin Consent onboarding URLs (`/api/auth/callback` & `/api/tenants/consent-callback`), per-tenant technician access scoping (`tenant_access`), per-session active tenant context, and structured connection test diagnostics (`[Pocket365 Tenant Test]`).
- `src/server/functions/` — TanStack Start `createServerFn` RPC endpoints. **Important:** Keep `src/server/functions/*.ts` files exporting *only* `createServerFn` functions (and TypeScript types) so Vite's client build cleanly strips all server imports.
- `src/routes/` — File-based UI pages and raw HTTP API routes (`src/routes/api/`).

---

## 3. Non-Negotiable Security Invariants
1. **Strict Server-Side RBAC:** Every mutating server function and API handler MUST `await requireRole(...)` or `await requireCapability(...)` server-side—never rely on hiding UI controls alone.
2. **Audit Every Mutation & Login:** Record an immutable D1 `audit_logs` entry for logins, RBAC denials, and every mutating Graph/settings/security action.
3. **Never Persist Cleartext Secrets in Logs or Unencrypted Columns:** Never write generated user passwords, Temporary Access Pass (TAP) codes, or BitLocker recovery keys into `audit_logs`, `jobs`, or `console.*` edge logs. When logging diagnostic information (e.g. `[Pocket365 Graph Auth]`), log only tenant and client identifiers and boolean flags (`hasSecret`, `hasCert`), never the secret value itself. Encrypt stored webhooks, cached tokens, and tenant credentials via `encryptSecret()` / `decryptSecret()`.
4. **Workers Compatibility:** Never import `node:fs`, `node:dns`, `node:net`, or native addons in production runtime code. Use Cloudflare bindings (`DB`, `POCKET365_KV`, `POCKET365_R2`, `POCKET365_QUEUE`) and Web/DoH `fetch()` APIs. Never run `setInterval` timers outside Cron/request handlers.
5. **Strict Tenant & Organization Isolation:** Never leak credentials, Graph tokens, D1 rows, KV keys, or R2 export objects across tenant/organization boundaries.

---

## 4. Phase Status
- **Phases 1–4 (Complete):** Full M365 console, Security Hardening & 5-tier RBAC, Commercial Tiering/Ed25519/Stripe Webhooks, Multi-Tenant MSP Command Center.
- **Phase CF-1 (Complete):** Full Cloudflare Workers migration (`cloudflare-module` + `wrangler.jsonc`), async Drizzle D1 database layer + Node 22 `node:sqlite` D1 Vitest harness, Cloudflare KV distributed rate limiting & encrypted Graph token caching, Cloudflare R2 compliance report archiving (`/api/exports/download`), DNS-over-HTTPS (`doh.ts`), Cloudflare Cron Triggers + Queues (`ctx.waitUntil` Free-tier fallback), Docker retirement, and Cloudflare CI/CD workflow.
- **Phase CF-2 (Complete):** `DEPLOYMENT_MODE=self_hosted|saas` enforcement (single-tenant vs multi-tenant MSP gating), D1 migration `0005_organizations` (`organizations` table + `organization_id` across all domain tables), organization provisioning service (`src/server/orgs/service.ts`), strict org isolation across D1 queries, KV Graph token keys, and R2 export paths, and mode-aware `AppShell` navigation.
- **Phase CF-3 (Complete):** Key-versioned `enc:v2:<keyId>:...` AES-256-GCM encryption with zero-downtime key rotation (`DATA_ENCRYPTION_KEY_ID`, `DATA_ENCRYPTION_PREVIOUS_KEYS`), self-hosted first-run `/setup` wizard (`src/routes/setup.tsx`, `src/server/setup/service.ts`) with bootstrap token lock, 1-click PowerShell Entra App bootstrap script + JSON auto-fill, live Graph permission verification, encrypted D1 config fallback, and 1-click "Deploy to Cloudflare" documentation.
- **Phase CF-4 (Complete):** Multi-tenant Entra OIDC (`/organizations` endpoint with strict `iss`/`tid` matching & consumer MSA rejection) auto-provisioning isolated SaaS organizations on first sign-in, pure-fetch Stripe Checkout & Customer Billing Portal (`src/server/billing/stripe-client.ts`, `/billing`), org-aware Stripe webhook sync (`checkout.session.completed` & subscription lifecycle), and zero-secret Admin Consent default onboarding.
- **Phase CF-5 (Complete):** Multi-tenant Admin Consent & credential resolution hardening:
  - Canonical redirect URI enforcement via `/api/auth/callback` to prevent `AADSTS50011` redirect mismatch during admin consent.
  - Bulletproof fallback credential resolution hierarchy (`tenant.clientId` $\to$ `cfg.graphClientId` $\to$ `effective.graphClientId` $\to$ `cfg.oidcClientId` $\to$ `effective.oidcClientId`) ensuring client credentials never resolve as empty string.
  - Automatic D1 auto-healing of blank `clientId` in existing `managed_tenants` database rows on query load.
  - Structured edge observability (`[Pocket365 Graph Auth]`, `[Pocket365 Tenant Test]`) with real-time Microsoft Graph token acquisition & error diagnostic logging for Cloudflare Workers log stream (`wrangler tail`).

---

## 5. Verification Workflow
Before committing or pushing, always run:
```bash
npm run build && npm run typecheck && npm run lint && npm test
```
Note: `npm run build` must run before `tsc --noEmit` on a fresh checkout so TanStack Start generates `src/routeTree.gen.ts`.
