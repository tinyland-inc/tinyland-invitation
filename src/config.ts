/**
 * Dependency injection configuration for InvitationService.
 *
 * All external dependencies (file I/O, crypto, TOTP, audit) are injected
 * through this configuration rather than imported directly.
 */

export interface InvitationConfig {
  /** Read a file and return its contents as a string */
  readFile: (path: string) => Promise<string>;
  /** Write a string to a file */
  writeFile: (path: string, data: string) => Promise<void>;
  /** Path to the invitations JSON file */
  invitesFilePath: string;
  /** Path to the admin users JSON file */
  adminUsersFilePath: string;

  /** Generate a unique identifier (replaces nanoid) */
  generateId: () => string;
  /** Hash a password with the given number of rounds (replaces bcrypt.hash) */
  hashPassword: (password: string, rounds: number) => Promise<string>;

  /** Generate a TOTP secret (replaces authenticator.generateSecret) */
  generateTotpSecret: () => string;
  /** Generate a key URI for TOTP (replaces authenticator.keyuri) */
  generateKeyUri: (account: string, issuer: string, secret: string) => string;
  /** Generate a QR code data URL from an otpauth URI (replaces qrcode.toDataURL) */
  generateQrCode: (otpauthUrl: string) => Promise<string>;

  /** Auth configuration values */
  authConfig: {
    invitation: { defaultExpiryHours: number };
    password: { bcryptRounds: number };
  };

  /** Log an audit event */
  auditLog: (eventType: string, data: Record<string, unknown>) => Promise<void>;

  /** Public URL base for building invitation links (replaces process.env.PUBLIC_URL) */
  publicUrl: string;
}

let currentConfig: InvitationConfig | null = null;

/**
 * Configure the invitation package with all required dependencies.
 * Must be called before any service methods are used.
 */
export function configure(config: InvitationConfig): void {
  currentConfig = config;
}

/**
 * Get the current configuration.
 * Throws if configure() has not been called.
 */
export function getConfig(): InvitationConfig {
  if (!currentConfig) {
    throw new Error(
      'tinyland-invitation is not configured. Call configure() before using the service.'
    );
  }
  return currentConfig;
}

/**
 * Reset the configuration (primarily for testing).
 */
export function resetConfig(): void {
  currentConfig = null;
}
