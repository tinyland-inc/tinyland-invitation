






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
}

let currentConfig: InvitationConfig | null = null;





export function configure(config: InvitationConfig): void {
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
