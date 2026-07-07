







import crypto from 'crypto';
import { getConfig } from './config.js';
import { InvitationError } from './errors.js';
import { defaultCanCreateInviteForRole } from './roles.js';
import type {
  AdminInvite,
  AdminUser,
  AdminRole,
  InvitationCreateOptions,
  InvitationAcceptData,
  InvitationResult,
  AcceptResult,
  InvitationStatistics,
} from './types.js';

export class InvitationService {
  private invitations: Map<string, AdminInvite> = new Map();
  private initialized = false;

  
  
  

  
  private async ensureInitialized(): Promise<void> {
    if (this.initialized) return;

    await this.loadInvitations();
    await this.cleanupExpired();
    this.initialized = true;
  }

  
  private async loadInvitations(): Promise<void> {
    const config = getConfig();
    try {
      const data = await config.readFile(config.invitesFilePath);
      const parsed: unknown = JSON.parse(data);

      
      const invitations: AdminInvite[] = Array.isArray(parsed)
        ? (parsed as AdminInvite[])
        : ((parsed as Record<string, unknown>).invites as AdminInvite[] ?? []);

      this.invitations.clear();
      for (const invite of invitations) {
        this.invitations.set(invite.token, invite);
      }
    } catch {
      
      this.invitations = new Map();
    }
  }

  
  private async saveInvitations(): Promise<void> {
    const config = getConfig();
    const invitations = Array.from(this.invitations.values());
    await config.writeFile(config.invitesFilePath, JSON.stringify(invitations, null, 2));
  }

  
  private async cleanupExpired(): Promise<void> {
    const now = new Date();
    let changed = false;

    for (const [token, invite] of this.invitations.entries()) {
      if (new Date(invite.expiresAt) < now || invite.usedAt) {
        this.invitations.delete(token);
        changed = true;
      }
    }

    if (changed) {
      await this.saveInvitations();
    }
  }

  
  
  

  




  async createInvitation(options: InvitationCreateOptions): Promise<InvitationResult> {
    await this.ensureInitialized();
    const config = getConfig();

    // Fail-closed authority gate (TIN-1607 R3). Throws InvitationError('forbidden')
    // when the creator does not strictly outrank the target role. Deliberately
    // OUTSIDE the try/catch so a denial can never be masked as a generic failure,
    // and a mis-wired consumer cannot silently mint an unrestricted invitation.
    if (
      !(await this.canCreateInviteForRole(
        options.createdBy,
        options.role,
        options.createdByRole,
      ))
    ) {
      throw new InvitationError(
        'Insufficient permissions to create invitation for this role',
        'forbidden',
      );
    }

    try {

      const token = crypto.randomBytes(32).toString('hex');
      const id = config.generateId();

      
      const totpSecret = config.generateTotpSecret();

      
      const expiresInHours = options.expiresInHours ?? config.authConfig.invitation.defaultExpiryHours;
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + expiresInHours);

      
      const invitation: AdminInvite = {
        id,
        token,
        role: options.role,
        createdBy: options.createdBy,
        createdByHandle: options.createdByHandle || options.createdBy,
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        temporaryTotpSecret: totpSecret,
        isActive: true,
      };

      
      this.invitations.set(token, invitation);
      await this.saveInvitations();

      
      const otpauth = config.generateKeyUri(
        options.handle || `invite-${id}`,
        'Tinyland.dev (Invite)',
        totpSecret,
      );
      const qrCode = await config.generateQrCode(otpauth);

      
      const inviteUrl = `${config.publicUrl}/admin/accept-invite?token=${token}`;

      
      await config.auditLog('INVITATION_CREATED', {
        invitationId: id,
        handle: options.handle,
        role: options.role,
        createdBy: options.createdBy,
      });

      return {
        success: true,
        invitation,
        inviteUrl,
        totpSecret,
        qrCode,
      };
    } catch (error) {
      console.error('Failed to create invitation:', error);
      return {
        success: false,
        error: 'Failed to create invitation',
      };
    }
  }

  



  async getInvitation(token: string): Promise<AdminInvite | null> {
    await this.ensureInitialized();

    const invitation = this.invitations.get(token);
    if (!invitation) return null;

    
    if (new Date(invitation.expiresAt) < new Date()) {
      return null;
    }

    
    if (invitation.usedAt) {
      return null;
    }

    return invitation;
  }

  



  async acceptInvitation(data: InvitationAcceptData): Promise<AcceptResult> {
    await this.ensureInitialized();
    const config = getConfig();

    try {
      
      const invitation = await this.getInvitation(data.token);
      if (!invitation) {
        return {
          success: false,
          error: 'Invalid or expired invitation',
        };
      }

      
      const existingUsers = await this.loadAdminUsers();
      if (existingUsers.some((u) => u.handle === data.handle)) {
        return {
          success: false,
          error: 'Handle already taken',
        };
      }

      
      const passwordHash = await config.hashPassword(
        data.password,
        config.authConfig.password.bcryptRounds,
      );

      
      const newUser: AdminUser = {
        id: config.generateId(),
        username: data.handle,
        handle: data.handle,
        email: '',
        passwordHash,
        role: invitation.role,
        totpEnabled: false,
        totpSecretId: undefined,
        isActive: true,
        needsOnboarding: true,
        onboardingStep: 0,
        firstLogin: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      
      existingUsers.push(newUser);
      await config.writeFile(
        config.adminUsersFilePath,
        JSON.stringify(existingUsers, null, 2),
      );

      
      invitation.usedAt = new Date().toISOString();
      invitation.usedBy = newUser.id;
      await this.saveInvitations();

      
      await config.auditLog('INVITATION_ACCEPTED', {
        invitationId: invitation.id,
        userId: newUser.id,
        handle: data.handle,
        role: invitation.role,
      });

      await config.auditLog('USER_CREATED', {
        userId: newUser.id,
        handle: data.handle,
        role: invitation.role,
        createdVia: 'invitation',
      });

      return {
        success: true,
        user: newUser,
        userId: newUser.id,
        needsOnboarding: true,
        tempTotpSecret: invitation.temporaryTotpSecret,
      };
    } catch (error) {
      console.error('Failed to accept invitation:', error);
      return {
        success: false,
        error: 'Failed to accept invitation',
      };
    }
  }

  
  async listPendingInvitations(): Promise<AdminInvite[]> {
    await this.ensureInitialized();

    const now = new Date();
    return Array.from(this.invitations.values()).filter(
      (invite) => new Date(invite.expiresAt) > now && !invite.usedAt,
    );
  }

  
  async revokeInvitation(token: string, revokedBy: string): Promise<boolean> {
    await this.ensureInitialized();
    const config = getConfig();

    const invitation = this.invitations.get(token);
    if (!invitation) return false;

    this.invitations.delete(token);
    await this.saveInvitations();

    await config.auditLog('INVITATION_REVOKED', {
      invitationId: invitation.id,
      action: 'revoked',
      revokedBy,
    });

    return true;
  }

  
  async extendInvitation(token: string, additionalHours: number): Promise<boolean> {
    await this.ensureInitialized();

    const invitation = this.invitations.get(token);
    if (!invitation || invitation.usedAt) return false;

    const newExpiry = new Date(invitation.expiresAt);
    newExpiry.setHours(newExpiry.getHours() + additionalHours);
    invitation.expiresAt = newExpiry.toISOString();

    await this.saveInvitations();
    return true;
  }

  
  async getStatistics(): Promise<InvitationStatistics> {
    await this.ensureInitialized();

    const now = new Date();
    const all = Array.from(this.invitations.values());

    return {
      total: all.length,
      pending: all.filter((i) => new Date(i.expiresAt) > now && !i.usedAt).length,
      expired: all.filter((i) => new Date(i.expiresAt) <= now && !i.usedAt).length,
      used: all.filter((i) => !!i.usedAt).length,
    };
  }

  
  
  

  



  // Role authority gate (TIN-1607 R3). A consumer MAY inject a bespoke policy via
  // config.canCreateInviteForRole (see config.ts); when none is supplied we fall
  // back to the real role-hierarchy check (defaultCanCreateInviteForRole), which
  // requires the creator to STRICTLY outrank the target. The default is never
  // permissive — an unwired consumer fails closed rather than minting
  // unrestricted invitations.
  private async canCreateInviteForRole(
    creatorId: string,
    targetRole: AdminRole,
    creatorRole?: AdminRole,
  ): Promise<boolean> {
    const config = getConfig();
    const gate = config.canCreateInviteForRole ?? defaultCanCreateInviteForRole;

    return gate({
      createdBy: creatorId,
      createdByRole: creatorRole,
      targetRole,
    });
  }

  
  private async loadAdminUsers(): Promise<AdminUser[]> {
    const config = getConfig();
    try {
      const data = await config.readFile(config.adminUsersFilePath);
      return JSON.parse(data) as AdminUser[];
    } catch {
      return [];
    }
  }
}





export const invitationService = new InvitationService();

export async function createInvitation(
  options: InvitationCreateOptions,
): Promise<InvitationResult> {
  return invitationService.createInvitation(options);
}

export async function acceptInvitation(data: InvitationAcceptData): Promise<AcceptResult> {
  return invitationService.acceptInvitation(data);
}

export async function getInvitation(token: string): Promise<AdminInvite | null> {
  return invitationService.getInvitation(token);
}
