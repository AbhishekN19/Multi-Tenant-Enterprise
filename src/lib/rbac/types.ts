import { OrgRole } from '@prisma/client';

/**
 * Resources that exist within the Multi-Tenant SaaS ecosystem
 */
export type Resource =
  | 'tenant'
  | 'membership'
  | 'asset'
  | 'audit_log'
  | 'billing'
  | 'security_settings'
  | 'onboarding';

/**
 * Granular actions that can be executed against resources
 */
export type Action =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'manage'
  | 'invite'
  | 'export'
  | 'approve';

/**
 * Permission rule definition:
 * An action may either be unconditionally permitted, denied,
 * or subject to dynamic context (e.g. only if resource.ownerId === userId)
 */
export interface PermissionRule {
  resource: Resource;
  action: Action;
  condition?: (context: PermissionContext) => boolean;
}

/**
 * Dynamic context passed when evaluating permissions
 * (Useful for fine-grained conditions like "is user the author?")
 */
export interface PermissionContext {
  userId?: string;
  targetUserId?: string;
  resourceOwnerId?: string;
  tenantId?: string;
  isOwner?: boolean;
}

/**
 * Custom Authorization Error returned when an RBAC check fails
 */
export class AuthorizationError extends Error {
  public readonly statusCode: number = 403;
  public readonly code: string = 'FORBIDDEN';
  public readonly resource: Resource;
  public readonly action: Action;
  public readonly role: OrgRole;

  constructor(role: OrgRole, action: Action, resource: Resource, message?: string) {
    super(
      message ??
        `Forbidden: Role '${role}' lacks permission to perform '${action}' on '${resource}'`
    );
    this.name = 'AuthorizationError';
    this.resource = resource;
    this.action = action;
    this.role = role;
  }
}
