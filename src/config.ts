






import { assertInvitationRoleAuthority } from './roles.js';
import type { InvitationRoleAuthority, InvitationRoleDecision } from './roles.js';

export interface InvitationConfig {
  
  readFile: (path: string) => Promise<string>;
  
  writeFile: (path: string, data: string) => Promise<void>;
  
  invitesFilePath: string;
  
  adminUsersFilePath: string;

  
  generateId: () => string;
  
  hashPassword: (password: string, rounds: number) => Promise<string>;

  
  generateTotpSecret: () => string;
  
  generateKeyUri: (account: string, issuer: string, secret: string) => string;
  
  generateQrCode: (otpauthUrl: string) => Promise<string>;

  
  authConfig: {
    invitation: { defaultExpiryHours: number };
    password: { bcryptRounds: number };
  };

  
  auditLog: (eventType: string, data: Record<string, unknown>) => Promise<void>;

  publicUrl: string;

  /** Required versioned rank authority. Missing or invalid authority denies. */
  roleAuthority: InvitationRoleAuthority;

  /** Optional consumer veto. It may narrow, but never widen, role authority. */
  canCreateInviteForRole?: (
    args: InvitationRoleDecision,
  ) => boolean | Promise<boolean>;
}

let currentConfig: InvitationConfig | null = null;





export function configure(config: InvitationConfig): void {
  assertInvitationRoleAuthority(config.roleAuthority);
  currentConfig = config;
}





export function getConfig(): InvitationConfig {
  if (!currentConfig) {
    throw new Error(
      'tinyland-invitation is not configured. Call configure() before using the service.'
    );
  }
  return currentConfig;
}




export function resetConfig(): void {
  currentConfig = null;
}
