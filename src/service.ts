/**
 * Streamlined Invitation Service
 * Manages admin user invitations with enhanced security and simplified flow.
 *
 * All external dependencies are injected via the config module.
 * Only Node.js built-in `crypto` is used directly.
 */

import crypto from 'crypto';
import { getConfig } from './config.js';
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

  // -------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------

  /** Lazy-initialize on first operation */
  private async ensureInitialized(): Promise<void> {
    if (this.initialized) return;

    await this.loadInvitations();
    await this.cleanupExpired();
    this.initialized = true;
  }

  /** Load invitations from the configured JSON file */
  private async loadInvitations(): Promise<void> {
    const config = getConfig();
    try {
      const data = await config.readFile(config.invitesFilePath);
      const parsed: unknown = JSON.parse(data);

      // Handle both legacy format {invites: [...]} and modern format [...]
      const invitations: AdminInvite[] = Array.isArray(parsed)
        ? (parsed as AdminInvite[])
        : ((parsed as Record<string, unknown>).invites as AdminInvite[] ?? []);

      this.invitations.clear();
      for (const invite of invitations) {
        this.invitations.set(invite.token, invite);
      }
    } catch {
      // File doesn't exist or is empty -- start fresh
      this.invitations = new Map();
    }
  }

  /** Persist the current invitations map to disk */
  private async saveInvitations(): Promise<void> {
    const config = getConfig();
    const invitations = Array.from(this.invitations.values());
    await config.writeFile(config.invitesFilePath, JSON.stringify(invitations, null, 2));
  }

  /** Remove expired and already-used invitations */
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

  // -------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------

  /**
   * Create a new invitation.
   *
   * Generates a secure token, TOTP secret, QR code, and invite URL.
   */
  async createInvitation(options: InvitationCreateOptions): Promise<InvitationResult> {
    await this.ensureInitialized();
    const config = getConfig();

    try {
      // Validate role permissions
      if (!this.canCreateInviteForRole(options.createdBy, options.role)) {
        return {
          success: false,
          error: 'Insufficient permissions to create invitation for this role',
        };
      }

      // Generate secure token
      const token = crypto.randomBytes(32).toString('hex');
      const id = config.generateId();

      // Generate temporary TOTP secret
      const totpSecret = config.generateTotpSecret();

      // Calculate expiration
      const expiresInHours = options.expiresInHours ?? config.authConfig.invitation.defaultExpiryHours;
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + expiresInHours);

      // Build invitation record
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

      // Persist
      this.invitations.set(token, invitation);
      await this.saveInvitations();

      // Generate QR code
      const otpauth = config.generateKeyUri(
        options.handle || `invite-${id}`,
        'Tinyland.dev (Invite)',
        totpSecret,
      );
      const qrCode = await config.generateQrCode(otpauth);

      // Build invitation URL
      const inviteUrl = `${config.publicUrl}/admin/accept-invite?token=${token}`;

      // Audit log
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

  /**
   * Retrieve an invitation by token.
   * Returns null when the invitation is expired, used, or nonexistent.
   */
  async getInvitation(token: string): Promise<AdminInvite | null> {
    await this.ensureInitialized();

    const invitation = this.invitations.get(token);
    if (!invitation) return null;

    // Check expiration
    if (new Date(invitation.expiresAt) < new Date()) {
      return null;
    }

    // Check if already used
    if (invitation.usedAt) {
      return null;
    }

    return invitation;
  }

  /**
   * Accept an invitation: validate token, create user, mark used.
   * TOTP setup is deferred to the onboarding flow.
   */
  async acceptInvitation(data: InvitationAcceptData): Promise<AcceptResult> {
    await this.ensureInitialized();
    const config = getConfig();

    try {
      // Get & validate invitation
      const invitation = await this.getInvitation(data.token);
      if (!invitation) {
        return {
          success: false,
          error: 'Invalid or expired invitation',
        };
      }

      // Check handle uniqueness
      const existingUsers = await this.loadAdminUsers();
      if (existingUsers.some((u) => u.handle === data.handle)) {
        return {
          success: false,
          error: 'Handle already taken',
        };
      }

      // Hash password
      const passwordHash = await config.hashPassword(
        data.password,
        config.authConfig.password.bcryptRounds,
      );

      // Create user WITHOUT TOTP enabled (deferred to onboarding)
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

      // Persist user
      existingUsers.push(newUser);
      await config.writeFile(
        config.adminUsersFilePath,
        JSON.stringify(existingUsers, null, 2),
      );

      // Mark invitation as used
      invitation.usedAt = new Date().toISOString();
      invitation.usedBy = newUser.id;
      await this.saveInvitations();

      // Audit logs
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

  /** List all pending (active, non-expired, non-used) invitations */
  async listPendingInvitations(): Promise<AdminInvite[]> {
    await this.ensureInitialized();

    const now = new Date();
    return Array.from(this.invitations.values()).filter(
      (invite) => new Date(invite.expiresAt) > now && !invite.usedAt,
    );
  }

  /** Revoke an invitation by token. Returns true on success. */
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

  /** Extend the expiration of an invitation. Returns false for used or missing invitations. */
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

  /** Get aggregate statistics about invitations */
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

  // -------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------

  /**
   * Check whether a creator is allowed to issue an invite for the given role.
   * Stub -- returns true. Extend with role-hierarchy logic as needed.
   */
  private canCreateInviteForRole(_creatorId: string, _targetRole: AdminRole): boolean {
    return true;
  }

  /** Load admin users from the configured JSON file */
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

// -------------------------------------------------------------------
// Singleton & convenience exports
// -------------------------------------------------------------------

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
