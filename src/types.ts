




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


export interface InvitationCreateOptions {
  handle?: string;
  role: AdminRole;
  createdBy: string;
  createdByHandle: string;
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
