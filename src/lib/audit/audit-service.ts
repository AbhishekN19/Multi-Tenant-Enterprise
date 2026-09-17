import { db } from '@/lib/prisma';
import { Resource } from '@/lib/rbac/types';

export interface AuditLogPayload {
  tenantId: string;
  userId?: string;
  action: string;
  resource: Resource | string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Creates an immutable audit log entry in PostgreSQL for SOC-2 / ISO compliance.
 */
export async function logAuditEvent(payload: AuditLogPayload) {
  try {
    return await db.auditLog.create({
      data: {
        tenantId: payload.tenantId,
        userId: payload.userId,
        action: payload.action,
        resource: payload.resource,
        resourceId: payload.resourceId,
        ipAddress: payload.ipAddress,
        userAgent: payload.userAgent,
        metadata: payload.metadata ? JSON.parse(JSON.stringify(payload.metadata)) : undefined,
      },
    });
  } catch (err) {
    console.error('[Audit Service Error]: Failed to persist audit trail record', err);
    throw err;
  }
}
