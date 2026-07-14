




// Intentionally widened to string for now (TIN-2526): role vocabularies are
// consumer-defined and enforced by the injected canCreateInviteForRole hook,
// so tightening this to a union here would break existing public API users.
export type AdminRole = string;


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


export interface InvitationPrincipal {
  readonly id: string;
  readonly role: AdminRole;
  readonly handle: string;
  readonly isActive: boolean;
}


export interface InvitationCreateOptions {
  handle?: string;
  role: AdminRole;
  expiresInHours?: number;
  message?: string;
  skipEmail?: boolean;
}


export interface InvitationAcceptData {
  token: string;
  handle: string;
  password: string;
}


export interface InvitationResult {
  success: boolean;
  invitation?: AdminInvite;
  inviteUrl?: string;
  totpSecret?: string;
  qrCode?: string;
  error?: string;
}


export interface AcceptResult {
  success: boolean;
  user?: AdminUser;
  userId?: string;
  needsOnboarding?: boolean;
  tempTotpSecret?: string;
  error?: string;
}


export interface InvitationStatistics {
  total: number;
  pending: number;
  expired: number;
  used: number;
}
