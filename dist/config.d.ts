import type { InvitationRoleAuthority, InvitationRoleDecision } from './roles.js';
import type { AdminRole } from './types.js';
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
        invitation: {
            defaultExpiryHours: number;
        };
        password: {
            bcryptRounds: number;
        };
    };
    auditLog: (eventType: string, data: Record<string, unknown>) => Promise<void>;
    publicUrl: string;
    /** Required versioned rank authority. Missing or invalid authority denies. */
    roleAuthority: InvitationRoleAuthority;
    /** Resolve role from a trusted server-side principal store by creator ID. */
    resolveCreatorRole: (createdBy: string) => AdminRole | null | Promise<AdminRole | null>;
    /** Optional consumer veto. It may narrow, but never widen, role authority. */
    canCreateInviteForRole?: (args: InvitationRoleDecision) => boolean | Promise<boolean>;
}
export declare function configure(config: InvitationConfig): void;
export declare function getConfig(): InvitationConfig;
export declare function resetConfig(): void;
//# sourceMappingURL=config.d.ts.map