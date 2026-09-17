import { OrgRole } from '@prisma/client';
import { Action, Resource, PermissionContext, AuthorizationError } from './types';
import { hasPermission } from './permissions';

/**
 * Asserts that the role has permission to execute the requested action.
 * Throws an AuthorizationError (HTTP 403 Forbidden) if denied.
 * 
 * This function is pure and decoupled from the database, allowing it
 * to run in Next.js middleware, edge runtime, server actions, or unit tests.
 */
export function assertPermission(
  role: OrgRole,
  action: Action,
  resource: Resource,
  context: PermissionContext = {}
): void {
  const allowed = hasPermission(role, action, resource, context);
  if (!allowed) {
    throw new AuthorizationError(role, action, resource);
  }
}

/**
 * Executes a protected action with permission checking and optional audit logging.
 */
export async function executeGuardedAction<T>(params: {
  role: OrgRole;
  action: Action;
  resource: Resource;
  tenantId: string;
  userId?: string;
  context?: PermissionContext;
  auditMetadata?: Record<string, unknown>;
  onAudit?: (payload: {
    tenantId: string;
    userId?: string;
    action: string;
    resource: Resource;
    metadata?: Record<string, unknown>;
  }) => Promise<void>;
  operation: () => Promise<T>;
}): Promise<T> {
  // 1. Enforce RBAC boundary (Throws HTTP 403 if unauthorized)
  assertPermission(params.role, params.action, params.resource, params.context);

  // 2. Perform the business logic
  const result = await params.operation();

  // 3. Optional audit log callback
  if (params.onAudit) {
    await params.onAudit({
      tenantId: params.tenantId,
      userId: params.userId,
      action: `${params.action.toUpperCase()}_${params.resource.toUpperCase()}`,
      resource: params.resource,
      metadata: params.auditMetadata,
    });
  }

  return result;
}
