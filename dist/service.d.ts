import type { AdminInvite, InvitationCreateOptions, InvitationAcceptData, InvitationResult, AcceptResult, InvitationStatistics } from './types.js';
export declare class InvitationService {
    private invitations;
    private initialized;
    private ensureInitialized;
    private loadInvitations;
    private saveInvitations;
    private cleanupExpired;
    createInvitation(options: InvitationCreateOptions): Promise<InvitationResult>;
    getInvitation(token: string): Promise<AdminInvite | null>;
    acceptInvitation(data: InvitationAcceptData): Promise<AcceptResult>;
    listPendingInvitations(): Promise<AdminInvite[]>;
    revokeInvitation(token: string, revokedBy: string): Promise<boolean>;
    extendInvitation(token: string, additionalHours: number): Promise<boolean>;
    getStatistics(): Promise<InvitationStatistics>;
    private canCreateInviteForRole;
    private loadAdminUsers;
}
export declare const invitationService: InvitationService;
export declare function createInvitation(options: InvitationCreateOptions): Promise<InvitationResult>;
export declare function acceptInvitation(data: InvitationAcceptData): Promise<AcceptResult>;
export declare function getInvitation(token: string): Promise<AdminInvite | null>;
//# sourceMappingURL=service.d.ts.map