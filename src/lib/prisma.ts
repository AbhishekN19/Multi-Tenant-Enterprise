import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';

/**
 * Prisma 7 Client with PostgreSQL Driver Adapter.
 * 
 * In development, Next.js clears Node cache on HMR (Hot Module Replacement),
 * which can cause new PrismaClient instances to be created on every file change,
 * quickly exhausting database connection pool limits.
 * 
 * Attaching both the pg Pool and PrismaClient to `globalThis` preserves
 * a single connection pool across hot reloads.
 */
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
  pool: Pool | undefined;
};

const connectionString =
  process.env.DATABASE_URL ||
  'postgresql://postgres:postgres@localhost:5432/saas_ops_dev?schema=public';

const pool = globalForPrisma.pool ?? new Pool({ connectionString });
const adapter = new PrismaPg(pool);

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter,
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = db;
  globalForPrisma.pool = pool;
}
