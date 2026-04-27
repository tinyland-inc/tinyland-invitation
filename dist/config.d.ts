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
}
export declare function configure(config: InvitationConfig): void;
export declare function getConfig(): InvitationConfig;
export declare function resetConfig(): void;
//# sourceMappingURL=config.d.ts.map