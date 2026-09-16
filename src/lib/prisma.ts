import { PrismaClient } from '@prisma/client';

/**
 * Prisma Client Singleton pattern for Next.js.
 * 
 * In development, Next.js clears Node cache on HMR (Hot Module Replacement),
 * which can cause new PrismaClient instances to be created on every file change,
 * quickly exhausting database connection pool limits.
 * 
 * Attaching it to `globalThis` preserves the single connection pool across hot reloads.
 */
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = db;
}
