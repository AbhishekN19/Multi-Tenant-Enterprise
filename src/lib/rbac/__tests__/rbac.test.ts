import { describe, it, expect } from 'vitest';
import { hasPermission } from '../permissions';
import { assertPermission } from '../guards';
import { AuthorizationError } from '../types';

describe('RBAC Permission Matrix & Security Guards', () => {
  describe('SUPER_ADMIN Permissions', () => {
    it('grants unconditional access to all resources and actions', () => {
      expect(hasPermission('SUPER_ADMIN', 'manage', 'tenant')).toBe(true);
      expect(hasPermission('SUPER_ADMIN', 'delete', 'tenant')).toBe(true);
      expect(hasPermission('SUPER_ADMIN', 'manage', 'billing')).toBe(true);
      expect(hasPermission('SUPER_ADMIN', 'manage', 'membership')).toBe(true);
    });
  });

  describe('ORG_ADMIN Permissions', () => {
    it('allows managing tenant, members, assets, and billing', () => {
      expect(hasPermission('ORG_ADMIN', 'manage', 'tenant')).toBe(true);
      expect(hasPermission('ORG_ADMIN', 'invite', 'membership')).toBe(true);
      expect(hasPermission('ORG_ADMIN', 'delete', 'membership')).toBe(true);
      expect(hasPermission('ORG_ADMIN', 'manage', 'billing')).toBe(true);
      expect(hasPermission('ORG_ADMIN', 'read', 'audit_log')).toBe(true);
    });

    it('denies mutating audit logs because they are immutable (SOC-2 requirement)', () => {
      expect(hasPermission('ORG_ADMIN', 'delete', 'audit_log')).toBe(false);
      expect(hasPermission('ORG_ADMIN', 'update', 'audit_log')).toBe(false);
    });
  });

  describe('MANAGER Permissions', () => {
    it('allows inviting members and managing team assets', () => {
      expect(hasPermission('MANAGER', 'invite', 'membership')).toBe(true);
      expect(hasPermission('MANAGER', 'read', 'asset')).toBe(true);
      expect(hasPermission('MANAGER', 'create', 'asset')).toBe(true);
      expect(hasPermission('MANAGER', 'read', 'audit_log')).toBe(true);
    });

    it('denies managing billing or deleting the organization', () => {
      expect(hasPermission('MANAGER', 'manage', 'billing')).toBe(false);
      expect(hasPermission('MANAGER', 'delete', 'tenant')).toBe(false);
      expect(hasPermission('MANAGER', 'delete', 'membership')).toBe(false);
    });

    it('enforces ownership conditions when deleting assets', () => {
      const myUserId = 'user_manager_1';
      const otherUserId = 'user_other_9';

      // Can delete own asset
      expect(
        hasPermission('MANAGER', 'delete', 'asset', {
          userId: myUserId,
          resourceOwnerId: myUserId,
        })
      ).toBe(true);

      // Cannot delete another user's asset
      expect(
        hasPermission('MANAGER', 'delete', 'asset', {
          userId: myUserId,
          resourceOwnerId: otherUserId,
        })
      ).toBe(false);
    });
  });

  describe('MEMBER Permissions', () => {
    it('allows standard collaboration but strictly blocks administrative tasks', () => {
      expect(hasPermission('MEMBER', 'read', 'tenant')).toBe(true);
      expect(hasPermission('MEMBER', 'read', 'membership')).toBe(true);
      expect(hasPermission('MEMBER', 'create', 'asset')).toBe(true);

      // Denied actions:
      expect(hasPermission('MEMBER', 'invite', 'membership')).toBe(false);
      expect(hasPermission('MEMBER', 'read', 'audit_log')).toBe(false);
      expect(hasPermission('MEMBER', 'read', 'billing')).toBe(false);
      expect(hasPermission('MEMBER', 'manage', 'security_settings')).toBe(false);
    });

    it('permits updating/deleting only self-owned assets', () => {
      const memberId = 'user_member_1';

      expect(
        hasPermission('MEMBER', 'update', 'asset', {
          userId: memberId,
          resourceOwnerId: memberId,
        })
      ).toBe(true);

      expect(
        hasPermission('MEMBER', 'update', 'asset', {
          userId: memberId,
          resourceOwnerId: 'user_different_2',
        })
      ).toBe(false);
    });
  });

  describe('AUDITOR Permissions (Compliance Role)', () => {
    it('allows read and export on audit logs, assets, and security settings', () => {
      expect(hasPermission('AUDITOR', 'read', 'audit_log')).toBe(true);
      expect(hasPermission('AUDITOR', 'export', 'audit_log')).toBe(true);
      expect(hasPermission('AUDITOR', 'read', 'asset')).toBe(true);
      expect(hasPermission('AUDITOR', 'read', 'security_settings')).toBe(true);
      expect(hasPermission('AUDITOR', 'read', 'billing')).toBe(true);
    });

    it('strictly forbids any state mutations (zero create, update, or delete)', () => {
      expect(hasPermission('AUDITOR', 'create', 'asset')).toBe(false);
      expect(hasPermission('AUDITOR', 'update', 'tenant')).toBe(false);
      expect(hasPermission('AUDITOR', 'delete', 'asset')).toBe(false);
      expect(hasPermission('AUDITOR', 'invite', 'membership')).toBe(false);
    });
  });

  describe('assertPermission() & AuthorizationError', () => {
    it('does not throw when an action is authorized', () => {
      expect(() => {
        assertPermission('ORG_ADMIN', 'invite', 'membership');
      }).not.toThrow();
    });

    it('throws an AuthorizationError with status 403 when forbidden', () => {
      expect(() => {
        assertPermission('MEMBER', 'manage', 'billing');
      }).toThrowError(AuthorizationError);

      try {
        assertPermission('AUDITOR', 'delete', 'asset');
      } catch (error) {
        expect(error).toBeInstanceOf(AuthorizationError);
        const authErr = error as AuthorizationError;
        expect(authErr.statusCode).toBe(403);
        expect(authErr.code).toBe('FORBIDDEN');
        expect(authErr.role).toBe('AUDITOR');
        expect(authErr.action).toBe('delete');
        expect(authErr.resource).toBe('asset');
      }
    });
  });
});
