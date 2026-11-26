import { defineConfig } from 'drizzle-kit'

/**
 * PostgreSQL Drizzle configuration for Phase 4+ horizontal SaaS deployments.
 * Default single-container Docker/Portainer deployments continue to use SQLite
 * via `drizzle.config.ts` with zero external database dependency.
 */
export default defineConfig({
  schema: './src/server/db/schema.ts',
  out: './drizzle-pg',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || 'postgresql://pocket365:pocket365@localhost:5432/pocket365',
  },
})
