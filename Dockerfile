# ==============================================================================
# Pocket365 Multi-Stage Production Dockerfile
# Targets Node.js 22 LTS (Alpine) with standalone Nitro Node server output
# ==============================================================================

FROM node:22-alpine AS builder

WORKDIR /app

# Native build toolchain for better-sqlite3 on Alpine (x86_64 / arm64)
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .

RUN npm run build && npm run typecheck

# ==============================================================================
# Minimal Non-Root Production Runtime Image
# ==============================================================================
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/data

# Create persistent SQLite volume mount point owned by non-root 'node' user
RUN mkdir -p /data && chown -R node:node /data /app

COPY --from=builder --chown=node:node /app/.output ./.output
COPY --from=builder --chown=node:node /app/package.json ./package.json

USER node

EXPOSE 3000

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", ".output/server/index.mjs"]
