/**
 * Type definitions for tinyland-invitation
 */

/** Role identifier for admin users */
export type AdminRole = string;

/** Represents a pending or completed invitation */
export interface AdminInvite {
  id: string;
  token: string;
  role: AdminRole;
  createdBy: string;
  createdByHandle: string;
  createdAt: string;
  expiresAt: string;
  temporaryTotpSecret?: string;
  isActive: boolean;
  usedAt?: string;
  usedBy?: string;
  [key: string]: unknown;
}

/** Represents an admin user account */
export interface AdminUser {
  id: string;
  username: string;
  handle: string;
  email: string;
  passwordHash: string;
  role: AdminRole;
  totpEnabled: boolean;
  totpSecretId?: string;
  isActive: boolean;
  needsOnboarding?: boolean;
  onboardingStep?: number;
  firstLogin?: boolean;
  createdAt: string;
  updatedAt: string;
  [key: string]: unknown;
}

/** Options for creating a new invitation */
export interface InvitationCreateOptions {
  handle?: string;
  role: AdminRole;
  createdBy: string;
  createdByHandle: string;
  expiresInHours?: number;
  message?: string;
  skipEmail?: boolean;
}

/** Data required to accept an invitation */
export interface InvitationAcceptData {
  token: string;
  handle: string;
  password: string;
}

/** Result returned from creating an invitation */
export interface InvitationResult {
  success: boolean;
  invitation?: AdminInvite;
  inviteUrl?: string;
  totpSecret?: string;
  qrCode?: string;
  error?: string;
}

/** Result returned from accepting an invitation */
export interface AcceptResult {
  success: boolean;
  user?: AdminUser;
  userId?: string;
  needsOnboarding?: boolean;
  tempTotpSecret?: string;
  error?: string;
}

/** Invitation statistics */
export interface InvitationStatistics {
  total: number;
  pending: number;
  expired: number;
  used: number;
}
