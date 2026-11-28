# Pocket365

**Pocket365** (`pocket365`) is a **Cloudflare-native** Microsoft 365 security, compliance, and **multi-tenant MSP** management web application — part of the **[Built by Vets](https://builtbyvets.app)** software suite. Built with **TanStack Start** (TanStack Router, TanStack Query, and Nitro v3 `cloudflare-module`), **Cloudflare Workers**, **D1 (SQLite)** + **Drizzle ORM**, **KV**, **R2**, **Cron Triggers**, **Queues**, and **Microsoft Entra ID OIDC** authentication.

Deploy to **your own Cloudflare account** in `self_hosted` mode (Free single-tenant starter or Pro single-tenant license), or operate as a **multi-tenant MSP SaaS** in `saas` mode using a single deployment flag (`DEPLOYMENT_MODE`). Unauthenticated visitors at `/` see the public Pocket365 landing page, while signed-in users go straight to the Dashboard.

---

## Core Capabilities

- **100% Cloudflare Full-Stack Runtime:**
  - **Cloudflare Workers:** Zero-cold-start edge SSR & API runtime (`wrangler.jsonc`, `nodejs_compat`).
  - **Cloudflare D1:** Edge SQLite via Drizzle ORM (`drizzle-orm/d1`) for sessions, audit logs, managed tenants, CIS history, alerts, onboarding templates, and licensing.
  - **Cloudflare KV (`POCKET365_KV`):** Distributed edge rate limiting + AES-256-GCM encrypted Graph OAuth token caching across isolates.
  - **Cloudflare R2 (`POCKET365_R2`):** Archived CIS compliance report snapshots (`/api/exports/download`).
  - **Cloudflare Cron Triggers & Queues:** Scheduled security/drift alert sweeps (`*/15 * * * *`) and async bulk job processing (with automatic `ctx.waitUntil()` fallback when `POCKET365_QUEUE` is unbound so Cloudflare Free plans work cleanly).
  - **DNS-over-HTTPS:** Pure-fetch DoH (`cloudflare-dns.com/dns-query`) for CIS SPF/DKIM/DMARC email auth audits and outbound webhook SSRF protection.
- **Entra ID OIDC Authentication & 5-Tier RBAC:**
  - Authorization Code + PKCE (`S256`), single-use `state` + browser cookie binding, `nonce`, RS256 JWKS signature verification.
  - Granular roles: `owner`, `admin`, `helpdesk`, `security_auditor`, and `viewer` enforced server-side (`403 Forbidden`) with immutable D1 audit logs.
- **Defense-in-Depth Security Baseline:**
  - Edge KV sliding-window rate limiting (`auth`, `api`, `mutation`, `heavy`), CSRF (`Origin` + `Sec-Fetch-Site`), strict HTTP security headers (CSP, HSTS, `X-Frame-Options: DENY`), AES-256-GCM secret encryption at rest, SSRF blocking, CSV formula-injection neutralization, and `/security` active sessions management.
- **Commercial Tiering & Licensing (`/billing`):**
  - `self_hosted` Free (`community`) vs Pro (`pro` offline Ed25519-signed license key), and `saas` (all features + multi-tenant MSP via Stripe).
- **Full M365 & MSP Feature Suite:**
  - Sign-in Logs Troubleshooting (AADSTS diagnosis), MFA Coverage Report, 24 CIS M365 Benchmarks + 16 1-click fixes + R2 report snapshots, Privileged Roles, Directory Audits, Users/Offboarding/Onboarding Templates, Groups, Mailbox BEC Sweep & Auto-Reply, Apps/OAuth Grants, Stale Cleanup, CA Drift, Devices/BitLocker, Automated Alerts, and Multi-Tenant MSP Command Center (`/tenants`).

---

## 1. Microsoft Entra ID App Registration Setup

### A. Interactive OIDC Login App (`OIDC_CLIENT_ID`)
1. Open **Microsoft Entra admin center** → **Identity** → **Applications** → **App registrations** → **New registration**.
2. Name: `Pocket365 Web`
3. Supported account types:
   - For `self_hosted`: **Accounts in this organizational directory only (Single tenant)**
   - For `saas`: **Accounts in any organizational directory (Multitenant)**
4. Redirect URI (Platform: **Web**):
   - `https://<your-worker-or-custom-domain>/api/auth/callback`
   > [!IMPORTANT]
   > The redirect URI MUST be registered under the **Web** platform and end with `/api/auth/callback`. This canonical URI handles both interactive user sign-ins and tenant Admin Consent onboarding. Omitting or altering it causes `AADSTS50011`.
5. Copy **Directory (tenant) ID** → `ENTRA_TENANT_ID`, **Application (client) ID** → `OIDC_CLIENT_ID`, and create a client secret → `OIDC_CLIENT_SECRET`.
6. *(Optional, recommended for group-based RBAC)* Under **Token configuration**, add the **Security groups** claim (Group ID).

### B. Microsoft Graph App-Only Registration (`GRAPH_CLIENT_ID`)
Grant Microsoft Graph **Application permissions** and click **Grant admin consent**:
- `User.ReadWrite.All`, `Group.ReadWrite.All`, `Organization.Read.All`, `Directory.Read.All`
- `AuditLog.Read.All`, `UserAuthenticationMethod.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`
- `Policy.Read.All`, `Policy.ReadWrite.Authorization`, `Policy.ReadWrite.SecurityDefaults`, `Policy.ReadWrite.ConsentRequest`, `Policy.ReadWrite.AuthenticationMethod`
- `SharePointTenantSettings.ReadWrite.All`, `Application.Read.All`, `DelegatedPermissionGrant.ReadWrite.All`
- `MailboxSettings.ReadWrite`, `Mail.ReadWrite`, `SecurityEvents.Read.All`
- *(Optional P1/P2/Intune)* `Policy.ReadWrite.ConditionalAccess`, `DeviceManagementManagedDevices.ReadWrite.All`, `BitlockerKey.Read.All`, `IdentityRiskyUser.ReadWrite.All`

Authenticate using either an **X.509 Certificate** (`GRAPH_CERT_THUMBPRINT` + `GRAPH_CERT_PRIVATE_KEY` secret — recommended) or a **Client Secret** (`GRAPH_CLIENT_SECRET`).

> [!TIP]
> If you are using a single unified App Registration for both interactive login and Graph API, you do not need to set `GRAPH_CLIENT_ID` or `GRAPH_CLIENT_SECRET` separately; Pocket365 automatically falls back to `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.

---

## 2. Deploy to Cloudflare Workers

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/bangsmackpow/pocket365)

### Option A — 1-Click Self-Hosted Browser Setup (`/setup`)
1. Click **Deploy to Cloudflare** (or run `npm run deploy` after provisioning D1, KV, and R2).
2. Set just two Cloudflare Worker secrets (`SESSION_SECRET`, `DATA_ENCRYPTION_KEY`) and optional `SETUP_BOOTSTRAP_TOKEN`.
3. Open `https://<your-worker-url>/setup` in your browser:
   - Copy & run the generated **1-Click PowerShell Bootstrap Script** to automatically create your Entra App Registration and grant Graph permissions.
   - Paste the single-line JSON output back into `/setup` to auto-fill all fields.
   - Click **Test Graph Connection**, then **Save & Lock Setup** (credentials are stored in D1 encrypted with key-versioned `enc:v2` AES-256-GCM).

### Option B — CLI Provisioning & Wrangler Secrets
```bash
npm install

# 1. Create D1 database, KV namespace, and R2 bucket
npx wrangler d1 create pocket365-db
npx wrangler kv namespace create POCKET365_KV
npx wrangler r2 bucket create pocket365-exports
```
Paste the returned `database_id` and KV `id` into `wrangler.jsonc`.

### B. Apply D1 Migrations & Set Secrets
```bash
# Apply SQLite schema migrations to remote D1
npm run db:migrate:remote

# Set required Worker secrets
npx wrangler secret put APP_BASE_URL
npx wrangler secret put ENTRA_TENANT_ID
npx wrangler secret put OIDC_CLIENT_ID
npx wrangler secret put OIDC_CLIENT_SECRET
npx wrangler secret put GRAPH_CLIENT_ID
npx wrangler secret put GRAPH_CLIENT_SECRET
npx wrangler secret put SESSION_SECRET
npx wrangler secret put DATA_ENCRYPTION_KEY
npx wrangler secret put ADMIN_OIDS_OR_GROUPS
```

### C. Build & Deploy
```bash
npm run deploy
```

---

## 3. Local Development & Testing

```bash
cp .env.example .dev.vars
# Edit .dev.vars with your local values

npm install
npm run db:migrate:local
npm run dev
```

### Useful Scripts
```bash
npm run build            # Production Vite + Nitro Cloudflare Workers build
npm run typecheck        # Strict TypeScript check
npm run lint             # ESLint check
npm test                 # Vitest unit tests (D1/node:sqlite, KV, R2, Auth, RBAC, Billing, Tenants)
npm run preview          # Run locally under Wrangler / Miniflare
npm run deploy           # Build & deploy to Cloudflare Workers
npm run db:migrate:local # Apply D1 migrations locally
npm run db:migrate:remote# Apply D1 migrations to remote D1
```

---

## 4. Operating in Hosted SaaS Mode (`DEPLOYMENT_MODE=saas`)

Set `DEPLOYMENT_MODE=saas` in your Cloudflare Worker vars/secrets along with:
- A **Multitenant** Entra App Registration (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `GRAPH_CLIENT_ID` + X.509 certificate `GRAPH_CERT_THUMBPRINT` / `GRAPH_CERT_PRIVATE_KEY`).
- Stripe secrets: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `STRIPE_PRICE_SAAS`.

How SaaS onboarding works with **zero customer client secrets**:
1. Any M365 organization admin clicks **Continue with Microsoft Entra ID** (`/organizations` OIDC endpoint; personal MSA accounts are rejected).
2. Pocket365 auto-provisions an isolated Organization keyed by their home Entra Tenant ID (`organization_id` scoping across D1, KV, and R2) and redirects them to `/billing`.
3. They subscribe via **Stripe Checkout** (with self-service **Stripe Billing Portal** for invoices/upgrades), unlocking all features and unlimited multi-tenant MSP management.
4. They connect customer M365 tenants via **1-Click Microsoft Admin Consent** (`/api/tenants/consent-callback`) — storing only the customer's public Tenant GUID, with zero per-customer secrets in D1.

---

## 5. Live Edge Observability & Troubleshooting

Pocket365 emits structured diagnostic events directly into Cloudflare's edge logging pipeline.

### A. Streaming Live Logs
- **Cloudflare Dashboard:** Go to **Workers & Pages** → **`pocket365`** → **Observability** → **Logs** → click **Begin log stream**.
- **Or via Wrangler CLI:**
  ```bash
  npx wrangler tail
  ```

### B. Structured Log Tags
- `[Pocket365 Graph Auth]` — Emitted during token acquisition. Logs the target tenant ID, client ID, authentication mechanism (`hasSecret`, `hasCert`), and any HTTP error codes returned by Microsoft's token endpoint (`https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token`).
- `[Pocket365 Tenant Test]` — Emitted when clicking **Test** on `/tenants`. Logs the tenant's connection mode, ID, and verified default domain on success, or the exact Graph error on failure.

### C. Common Entra ID Errors & Fixes
| Error Code | Meaning | Remediation |
|---|---|---|
| `AADSTS50011` | Redirect URI mismatch | Verify that `https://<domain>/api/auth/callback` is listed under the **Web** platform in your Azure Portal App Registration Redirect URIs. |
| `AADSTS700016` | App not installed or consented in tenant | The customer tenant administrator has not yet granted consent. Use the 1-click **Grant Admin Consent** link generated on `/tenants`. |
| `AADSTS65004` | User or administrator declined consent | Re-open the Admin Consent URL and have an Entra Global Administrator click **Accept**. |

---

## 6. GitHub Actions CI / CD

[`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) runs `build`, `typecheck`, `lint`, `test`, and `npm audit --omit=dev --audit-level=high` on every PR and push to `main`.

To enable automatic Cloudflare Workers deployment on pushes to `main`:
1. Add repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.
2. Add repository variable `CLOUDFLARE_DEPLOY_ENABLED=true`.
