import { OrgRole } from '@prisma/client';
import { Action, Resource, PermissionRule, PermissionContext } from './types';

/**
 * Enterprise RBAC Permission Matrix
 * Maps each Organization Role to explicit allowed actions and resources.
 * Supports static permissions and dynamic contextual conditions (e.g. resource ownership).
 */
export const PERMISSION_MATRIX: Record<OrgRole, PermissionRule[]> = {
  SUPER_ADMIN: [
    // Global platform admin has wildcard access
    { resource: 'tenant', action: 'manage' },
    { resource: 'tenant', action: 'read' },
    { resource: 'tenant', action: 'update' },
    { resource: 'tenant', action: 'delete' },
    { resource: 'membership', action: 'manage' },
    { resource: 'membership', action: 'invite' },
    { resource: 'membership', action: 'read' },
    { resource: 'membership', action: 'update' },
    { resource: 'membership', action: 'delete' },
    { resource: 'asset', action: 'manage' },
    { resource: 'asset', action: 'create' },
    { resource: 'asset', action: 'read' },
    { resource: 'asset', action: 'update' },
    { resource: 'asset', action: 'delete' },
    { resource: 'asset', action: 'export' },
    { resource: 'audit_log', action: 'read' },
    { resource: 'audit_log', action: 'export' },
    { resource: 'billing', action: 'manage' },
    { resource: 'billing', action: 'read' },
    { resource: 'billing', action: 'update' },
    { resource: 'security_settings', action: 'manage' },
    { resource: 'security_settings', action: 'read' },
    { resource: 'security_settings', action: 'update' },
    { resource: 'onboarding', action: 'manage' },
    { resource: 'onboarding', action: 'create' },
    { resource: 'onboarding', action: 'read' },
    { resource: 'onboarding', action: 'update' },
    { resource: 'onboarding', action: 'approve' },
  ],

  ORG_ADMIN: [
    // Organization owner - manages entire tenant workspace, users, and settings
    { resource: 'tenant', action: 'read' },
    { resource: 'tenant', action: 'update' },
    { resource: 'tenant', action: 'delete' },
    { resource: 'tenant', action: 'manage' },
    { resource: 'membership', action: 'manage' },
    { resource: 'membership', action: 'invite' },
    { resource: 'membership', action: 'read' },
    { resource: 'membership', action: 'update' },
    { resource: 'membership', action: 'delete' },
    { resource: 'asset', action: 'create' },
    { resource: 'asset', action: 'read' },
    { resource: 'asset', action: 'update' },
    { resource: 'asset', action: 'delete' },
    { resource: 'asset', action: 'export' },
    // Note: In SOC-2 compliance, audit logs are append-only.
    // Even an ORG_ADMIN cannot delete or update audit logs!
    { resource: 'audit_log', action: 'read' },
    { resource: 'audit_log', action: 'export' },
    { resource: 'billing', action: 'manage' },
    { resource: 'billing', action: 'read' },
    { resource: 'billing', action: 'update' },
    { resource: 'security_settings', action: 'manage' },
    { resource: 'security_settings', action: 'read' },
    { resource: 'security_settings', action: 'update' },
    { resource: 'onboarding', action: 'manage' },
    { resource: 'onboarding', action: 'create' },
    { resource: 'onboarding', action: 'read' },
    { resource: 'onboarding', action: 'update' },
    { resource: 'onboarding', action: 'approve' },
  ],

  MANAGER: [
    // Team lead - can invite members, manage project assets, cannot alter billing/tenancy
    { resource: 'tenant', action: 'read' },
    { resource: 'membership', action: 'read' },
    { resource: 'membership', action: 'invite' },
    { resource: 'asset', action: 'create' },
    { resource: 'asset', action: 'read' },
    { resource: 'asset', action: 'export' },
    {
      resource: 'asset',
      action: 'delete',
      condition: (ctx) =>
        Boolean(ctx.isOwner || (ctx.userId && ctx.userId === ctx.resourceOwnerId)),
    },
    { resource: 'audit_log', action: 'read' },
    { resource: 'security_settings', action: 'read' },
    { resource: 'onboarding', action: 'read' },
    { resource: 'onboarding', action: 'update' },
  ],

  MEMBER: [
    // Regular contributor - access limited to working with assets, editing own assets
    { resource: 'tenant', action: 'read' },
    { resource: 'membership', action: 'read' },
    { resource: 'asset', action: 'create' },
    { resource: 'asset', action: 'read' },
    {
      resource: 'asset',
      action: 'update',
      condition: (ctx) =>
        Boolean(ctx.isOwner || (ctx.userId && ctx.userId === ctx.resourceOwnerId)),
    },
    {
      resource: 'asset',
      action: 'delete',
      condition: (ctx) =>
        Boolean(ctx.isOwner || (ctx.userId && ctx.userId === ctx.resourceOwnerId)),
    },
    { resource: 'onboarding', action: 'read' },
  ],

  AUDITOR: [
    // Read-only auditor role for SOC 2 / ISO compliance. Zero mutation permissions.
    { resource: 'tenant', action: 'read' },
    { resource: 'membership', action: 'read' },
    { resource: 'asset', action: 'read' },
    { resource: 'asset', action: 'export' },
    { resource: 'audit_log', action: 'read' },
    { resource: 'audit_log', action: 'export' },
    { resource: 'billing', action: 'read' },
    { resource: 'security_settings', action: 'read' },
    { resource: 'onboarding', action: 'read' },
  ],
};

/**
 * Checks whether a given role is allowed to perform an action on a resource.
 *
 * @param role The role assigned to the user within the active tenant
 * @param action The operation to perform ('create' | 'read' | 'update' | 'delete' etc.)
 * @param resource The domain resource ('tenant' | 'membership' | 'asset' | 'audit_log' etc.)
 * @param context Dynamic context such as userId, resourceOwnerId, etc.
 * @returns boolean True if authorized, false otherwise
 */
export function hasPermission(
  role: OrgRole,
  action: Action,
  resource: Resource,
  context: PermissionContext = {}
): boolean {
  // SUPER_ADMIN has platform-wide wildcard access
  if (role === 'SUPER_ADMIN') {
    return true;
  }

  const rules = PERMISSION_MATRIX[role] ?? [];

  // Search for an exact match rule for this resource and action
  const matchedRule = rules.find(
    (rule) =>
      rule.resource === resource &&
      (rule.action === action || rule.action === 'manage')
  );

  if (!matchedRule) {
    return false;
  }

  // If the rule contains a dynamic condition, evaluate it with the context
  if (matchedRule.condition) {
    return matchedRule.condition(context);
  }

  return true;
}
