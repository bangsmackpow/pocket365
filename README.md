# Pocket365

**Pocket365** (`pocket365`) is a production-ready, self-hosted, **single-tenant** Microsoft 365 management web application built with **TanStack Start** (TanStack Router, TanStack Query, and Nitro Node server output), **Node.js 22 LTS**, **TypeScript**, **SQLite + Drizzle ORM**, and **Microsoft Entra ID OIDC** authentication.

Designed for clean container deployment via **GitHub Actions → GHCR → Portainer** behind **Nginx Proxy Manager**.

---

## Core Capabilities

- **Single-Tenant Entra ID OIDC Authentication:** Authorization Code flow with PKCE (`S256`), single-use `state` + browser cookie binding, `nonce` verification, and RS256 JWKS signature + `iss`/`aud`/`tid` validation.
- **Strict Two-Role RBAC (`viewer` vs `admin`):**
  - `viewer` (`read-only`): Inspect dashboard, licenses, users, groups, audit logs, and background jobs. Cannot trigger mutations.
  - `admin` (`full-admin`): Full access to directory/license/group mutations, bulk jobs, and non-secret runtime settings.
  - Every mutating server function and API handler enforces `requireRole('admin')` server-side (`403 Forbidden`) and writes an immutable SQLite audit trail.
  - Unmapped Entra users are strictly rejected.
- **App-Only Microsoft Graph Client:** Supports **Client Secret** or **X.509 Certificate (`RS256` + `x5t`)** authentication, token caching, automatic 401 refresh, and `429 Too Many Requests` (`Retry-After`) + `503`/`504` exponential backoff.
- **SQLite Persistence & Async Job Runner:** Stored at `/data/pocket365.db` (defaults to `./data/pocket365.db` locally) with WAL mode, auto-migrations on startup, server-side sessions, audit log, runtime settings, and background bulk job execution.
- **Reverse Proxy Ready:** Respects `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For`, uses `APP_BASE_URL` for OIDC redirect URIs, and sets `HttpOnly`, `Secure`, `SameSite=Lax` cookies automatically over HTTPS.

---

## 1. Microsoft Entra ID App Registration Setup

You can use either **one** App Registration for both OIDC login and Graph App-Only calls, or **two separate** registrations (recommended for least-privilege separation).

### A. Interactive OIDC Login App (`OIDC_CLIENT_ID`)
1. Open **Microsoft Entra admin center** → **Identity** → **Applications** → **App registrations** → **New registration**.
2. Name: `Pocket365 Web`
3. Supported account types: **Accounts in this organizational directory only (Single tenant)**.
4. Redirect URI:
   - Platform: **Web**
   - URI: `https://pocket365.example.com/api/auth/callback` (for local dev, also add `http://localhost:3000/api/auth/callback`)
5. Copy **Directory (tenant) ID** → `ENTRA_TENANT_ID` and **Application (client) ID** → `OIDC_CLIENT_ID`.
6. Go to **Certificates & secrets** → **New client secret** → copy value to `OIDC_CLIENT_SECRET`.
7. *(Optional, recommended for group-based RBAC)* Go to **Token configuration** → **Add groups claim** → select **Security groups** (emit **Group ID** in ID tokens). If a user exceeds Entra's group overage limit, Pocket365 automatically falls back to Microsoft Graph when configured.

### B. Microsoft Graph App-Only Registration (`GRAPH_CLIENT_ID`)
1. Create (or reuse) a **Single tenant** App Registration (`Pocket365 Graph Daemon`).
2. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**:
   - `User.ReadWrite.All` *(list/search users, toggle `accountEnabled`, assign/remove licenses, offboarding)*
   - `Group.ReadWrite.All` *(list/search groups, read/add/remove group members)*
   - `Organization.Read.All` *(read tenant summary and `subscribedSkus` license pools)*
   - `AuditLog.Read.All` *(troubleshoot Entra sign-in logs and directory audit logs)*
   - `Directory.Read.All` *(fallback group lookup on login and directory metadata)*
3. Click **Grant admin consent for `<Your Tenant>`** and confirm all permissions show green checkmarks.
4. Configure credentials using **one** of:
   - **Client Secret:** Create a secret under **Certificates & secrets** → set `GRAPH_CLIENT_SECRET`.
   - **X.509 Certificate (Recommended for production):** Upload your `.cer` public certificate under **Certificates & secrets** → **Certificates**, copy the **Thumbprint** (40 hex chars) to `GRAPH_CERT_THUMBPRINT`, and supply the matching PKCS#8 PEM private key via `GRAPH_CERT_PRIVATE_KEY` or mounted file `GRAPH_CERT_PRIVATE_KEY_PATH`.

---

## 2. Local Development

```bash
cp .env.example .env
# Edit .env with your ENTRA_TENANT_ID, OIDC_*, GRAPH_*, SESSION_SECRET, and ADMIN_OIDS_OR_GROUPS

npm install
npm run dev
```

Pocket365 starts at `http://localhost:3000` and auto-creates `./data/pocket365.db` on startup.

### Useful Scripts

```bash
npm run typecheck   # Strict TypeScript check
npm run lint        # ESLint check
npm test            # Vitest unit tests (Auth, OIDC, RBAC, Graph retries, Async Jobs)
npm run build       # Production Vite + Nitro Node build (.output/server/index.mjs)
npm start           # Run compiled production server
```

---

## 3. Nginx Proxy Manager Setup

1. Ensure Pocket365 and Nginx Proxy Manager share a Docker network (e.g., `npm_network`).
2. In **Nginx Proxy Manager**, add a new **Proxy Host**:
   - **Domain Names:** `pocket365.example.com`
   - **Scheme:** `http`
   - **Forward Hostname / IP:** `pocket365`
   - **Forward Port:** `3000`
   - **Block Common Exploits:** Enabled
   - **Websockets Support:** Optional (safe to enable)
3. Under the **SSL** tab:
   - Select or request a Let's Encrypt SSL certificate for `pocket365.example.com`.
   - Enable **Force SSL** and **HTTP/2 Support**.
4. Nginx Proxy Manager automatically passes `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-For`. Ensure `APP_BASE_URL=https://pocket365.example.com` matches the exact public hostname (no trailing slash).

---

## 4. GitHub Actions & GHCR Permissions

The included [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) workflow:
- Runs `typecheck`, `lint`, `test`, and `build` on every Pull Request and push to `main`.
- On pushes to `main` (and `v*.*.*` tags), builds the multi-stage Docker image with GitHub Actions cache (`type=gha`) and publishes it to:
  - `ghcr.io/bangsmackpow/pocket365:latest`
  - `ghcr.io/bangsmackpow/pocket365:<short-sha>`
  - Branch & SemVer tags

Ensure repository workflow permissions allow publishing packages:
1. Go to GitHub **Repository Settings** → **Actions** → **General** → **Workflow permissions**.
2. Confirm `GITHUB_TOKEN` has read/write permissions (the workflow explicitly scopes `packages: write` on the `docker` job).
3. If the GHCR package is private, create a GitHub PAT (`read:packages`) and add it under **Portainer → Registries** for `ghcr.io`.

---

## 5. Deploying & Updating in Portainer

1. Ensure the shared proxy network exists on your Docker host:
   ```bash
   docker network create npm_network
   ```
2. In **Portainer**, navigate to **Stacks** → **Add stack**:
   - Name: `pocket365`
   - Paste the contents of [`docker-compose.yml`](docker-compose.yml) (or link directly to `https://github.com/bangsmackpow/pocket365.git`).
   - Confirm the image is set to `ghcr.io/bangsmackpow/pocket365:latest`.
3. Add the required environment variables in Portainer's **Environment variables** editor:
   - `APP_BASE_URL` (e.g., `https://pocket365.example.com`)
   - `ENTRA_TENANT_ID`
   - `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`
   - `SESSION_SECRET` (generate via `openssl rand -hex 32`)
   - `ADMIN_OIDS_OR_GROUPS`, `VIEWER_OIDS_OR_GROUPS`
   - `GRAPH_CLIENT_ID`, and either `GRAPH_CLIENT_SECRET` or `GRAPH_CERT_THUMBPRINT` + `GRAPH_CERT_PRIVATE_KEY`
   - `PROXY_NETWORK` *(defaults to `npm_network`)*
4. Click **Deploy the stack**. Verify readiness at `https://pocket365.example.com/api/health`.
5. **Updating:** In Portainer → **Stacks** → `pocket365` → **Editor** → **Update the stack** with **Re-pull image and redeploy** enabled. SQLite data persists safely in the `pocket365_data` volume (`/data/pocket365.db`).
