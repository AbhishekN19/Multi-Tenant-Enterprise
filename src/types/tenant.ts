import { OrgRole, OrgPlan, OnboardingStatus } from '@prisma/client';

export type { OrgRole, OrgPlan, OnboardingStatus };

/**
 * Tenant / Organization basic info
 */
export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  domain?: string | null;
  plan: OrgPlan;
  onboardingStatus: OnboardingStatus;
  onboardingStep: number;
  createdAt: Date;
}

/**
 * User representation within an active session
 */
export interface SessionUser {
  id: string;
  email: string;
  name?: string | null;
  avatarUrl?: string | null;
  isSystemAdmin: boolean;
}

/**
 * Multi-Tenant Context: Identifies who is acting within WHICH tenant, and with what Role
 */
export interface TenantContext {
  user: SessionUser;
  tenant: TenantInfo;
  role: OrgRole;
}
