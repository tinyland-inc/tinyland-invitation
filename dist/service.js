import crypto from 'crypto';
import { getConfig } from './config.js';
import { InvitationError } from './errors.js';
import { authorityAllowsInvitation } from './roles.js';
const acceptanceLocks = new Map();
const failedAcceptanceClaims = new Set();
const INVITATION_PRINCIPAL_KEYS = ['id', 'role', 'handle', 'isActive'];
function ownDataProperty(value, key) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
function toInvitationPrincipal(value) {
    if (typeof value !== 'object' || value === null) {
        return null;
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length !== INVITATION_PRINCIPAL_KEYS.length ||
        !INVITATION_PRINCIPAL_KEYS.every((key) => keys.includes(key))) {
        return null;
    }
    const id = ownDataProperty(value, 'id');
    const role = ownDataProperty(value, 'role');
    const handle = ownDataProperty(value, 'handle');
    const isActive = ownDataProperty(value, 'isActive');
    if (typeof id !== 'string' ||
        id.trim().length === 0 ||
        typeof role !== 'string' ||
        role.trim().length === 0 ||
        typeof handle !== 'string' ||
        handle.trim().length === 0 ||
        typeof isActive !== 'boolean') {
        return null;
    }
    return Object.freeze({ id, role, handle, isActive });
}
// This serializes a token across every InvitationService instance in one Node
// process. It is deliberately not presented as cross-process or cross-replica
// compare-and-set; consumers that share storage across replicas still need a
// storage-backed CAS before they can claim distributed exactly-once semantics.
async function withAcceptanceLock(key, operation) {
    let release;
    const current = new Promise((resolve) => {
        release = resolve;
    });
    const previous = acceptanceLocks.get(key);
    acceptanceLocks.set(key, current);
    if (previous) {
        await previous;
    }
    try {
        return await operation();
    }
    finally {
        release();
        if (acceptanceLocks.get(key) === current) {
            acceptanceLocks.delete(key);
        }
    }
}
export class InvitationService {
    invitations = new Map();
    initialized = false;
    async ensureInitialized() {
        if (this.initialized)
            return;
        await this.loadInvitations();
        await this.cleanupExpired();
        this.initialized = true;
    }
    async loadInvitations() {
        const config = getConfig();
        try {
            const data = await config.readFile(config.invitesFilePath);
            const parsed = JSON.parse(data);
            const invitations = Array.isArray(parsed)
                ? parsed
                : (parsed.invites ?? []);
            this.invitations.clear();
            for (const invite of invitations) {
                this.invitations.set(invite.token, invite);
            }
        }
        catch {
            this.invitations = new Map();
        }
    }
    async saveInvitations() {
        const config = getConfig();
        const invitations = Array.from(this.invitations.values());
        await config.writeFile(config.invitesFilePath, JSON.stringify(invitations, null, 2));
    }
    async cleanupExpired() {
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
    async createInvitation(serverAuthContext, options) {
        const principal = await this.resolveInvitationPrincipal(serverAuthContext);
        // Fail-closed authority gate (TIN-1607 R3). Throws InvitationError('forbidden')
        // when the creator does not strictly outrank the target role. Deliberately
        // OUTSIDE the try/catch so a denial can never be masked as a generic failure,
        // and a mis-wired consumer cannot silently mint an unrestricted invitation.
        if (!principal || !(await this.canCreateInviteForRole(principal, options.role))) {
            throw new InvitationError('Insufficient permissions to create invitation for this role', 'forbidden');
        }
        await this.ensureInitialized();
        const config = getConfig();
        try {
            const token = crypto.randomBytes(32).toString('hex');
            const id = config.generateId();
            const totpSecret = config.generateTotpSecret();
            const expiresInHours = options.expiresInHours ?? config.authConfig.invitation.defaultExpiryHours;
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + expiresInHours);
            const invitation = {
                id,
                token,
                role: options.role,
                createdBy: principal.id,
                createdByHandle: principal.handle,
                createdAt: new Date().toISOString(),
                expiresAt: expiresAt.toISOString(),
                temporaryTotpSecret: totpSecret,
                isActive: true,
            };
            this.invitations.set(token, invitation);
            await this.saveInvitations();
            const otpauth = config.generateKeyUri(options.handle || `invite-${id}`, 'Tinyland.dev (Invite)', totpSecret);
            const qrCode = await config.generateQrCode(otpauth);
            const inviteUrl = `${config.publicUrl}/admin/accept-invite?token=${token}`;
            await config.auditLog('INVITATION_CREATED', {
                invitationId: id,
                handle: options.handle,
                role: options.role,
                createdBy: principal.id,
                createdByRole: principal.role,
                createdByHandle: principal.handle,
            });
            return {
                success: true,
                invitation,
                inviteUrl,
                totpSecret,
                qrCode,
            };
        }
        catch (error) {
            console.error('Failed to create invitation:', error);
            return {
                success: false,
                error: 'Failed to create invitation',
            };
        }
    }
    async getInvitation(token) {
        await this.ensureInitialized();
        return this.getPendingInvitation(token);
    }
    getPendingInvitation(token) {
        const invitation = this.invitations.get(token);
        if (!invitation)
            return null;
        if (new Date(invitation.expiresAt) < new Date()) {
            return null;
        }
        if (invitation.usedAt) {
            return null;
        }
        return invitation;
    }
    async acceptInvitation(data) {
        const config = getConfig();
        const lockKey = `${config.invitesFilePath}\0${data.token}`;
        return withAcceptanceLock(lockKey, async () => {
            await this.ensureInitialized();
            try {
                // Re-read the whole-file authority after entering the token lock. This
                // closes stale reads from route guards and other service instances in
                // this process. A read or parse failure empties the map and therefore
                // denies acceptance rather than trusting stale in-memory state.
                await this.loadInvitations();
                const invitation = failedAcceptanceClaims.has(lockKey)
                    ? null
                    : this.getPendingInvitation(data.token);
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
                const userId = config.generateId();
                // Claim first. Once validation succeeds, any later hash, user-file, or
                // audit failure leaves the token consumed instead of reopening a
                // role-bearing capability. If persistence itself fails, retain a
                // process-local deny marker for the remainder of this process.
                invitation.usedAt = new Date().toISOString();
                invitation.usedBy = userId;
                try {
                    await this.saveInvitations();
                }
                catch (error) {
                    failedAcceptanceClaims.add(lockKey);
                    throw error;
                }
                const passwordHash = await config.hashPassword(data.password, config.authConfig.password.bcryptRounds);
                const newUser = {
                    id: userId,
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
                await config.writeFile(config.adminUsersFilePath, JSON.stringify(existingUsers, null, 2));
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
            }
            catch (error) {
                console.error('Failed to accept invitation:', error);
                return {
                    success: false,
                    error: 'Failed to accept invitation',
                };
            }
        });
    }
    async listPendingInvitations() {
        await this.ensureInitialized();
        const now = new Date();
        return Array.from(this.invitations.values()).filter((invite) => new Date(invite.expiresAt) > now && !invite.usedAt);
    }
    async revokeInvitation(token, revokedBy) {
        await this.ensureInitialized();
        const config = getConfig();
        const invitation = this.invitations.get(token);
        if (!invitation)
            return false;
        this.invitations.delete(token);
        await this.saveInvitations();
        await config.auditLog('INVITATION_REVOKED', {
            invitationId: invitation.id,
            action: 'revoked',
            revokedBy,
        });
        return true;
    }
    async extendInvitation(token, additionalHours) {
        await this.ensureInitialized();
        const invitation = this.invitations.get(token);
        if (!invitation || invitation.usedAt)
            return false;
        const newExpiry = new Date(invitation.expiresAt);
        newExpiry.setHours(newExpiry.getHours() + additionalHours);
        invitation.expiresAt = newExpiry.toISOString();
        await this.saveInvitations();
        return true;
    }
    async getStatistics() {
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
    async resolveInvitationPrincipal(serverAuthContext) {
        const config = getConfig();
        try {
            const principal = toInvitationPrincipal(await config.resolveInvitationPrincipal(serverAuthContext));
            return principal?.isActive === true ? principal : null;
        }
        catch (error) {
            await this.auditPrincipalResolutionFailure(error);
            return null;
        }
    }
    async auditPrincipalResolutionFailure(error) {
        const config = getConfig();
        try {
            await config.auditLog('INVITATION_PRINCIPAL_RESOLUTION_ERROR', {
                reason: 'resolver_error',
                errorType: error instanceof Error ? error.name : typeof error,
            });
        }
        catch (auditError) {
            console.error('Failed to audit invitation principal resolution error:', auditError);
        }
    }
    // The versioned authority makes the rank decision. A consumer hook can add a
    // narrower realm rule, but it cannot turn an authority denial into an allow.
    async canCreateInviteForRole(principal, targetRole) {
        const config = getConfig();
        const decision = Object.freeze({
            principal,
            targetRole,
        });
        let authorityAllowed = false;
        try {
            authorityAllowed = await authorityAllowsInvitation(config.roleAuthority, decision);
        }
        catch (error) {
            await this.auditRoleAuthorityFailure('authority_error', decision, error);
            return false;
        }
        if (!authorityAllowed) {
            return false;
        }
        if (!config.canCreateInviteForRole) {
            return true;
        }
        try {
            return (await config.canCreateInviteForRole(decision)) === true;
        }
        catch (error) {
            await this.auditRoleAuthorityFailure('narrowing_hook_error', decision, error);
            return false;
        }
    }
    async auditRoleAuthorityFailure(reason, decision, error) {
        const config = getConfig();
        try {
            await config.auditLog('INVITATION_ROLE_AUTHORITY_ERROR', {
                reason,
                createdBy: decision.principal.id,
                createdByRole: decision.principal.role,
                createdByHandle: decision.principal.handle,
                targetRole: decision.targetRole,
                errorType: error instanceof Error ? error.name : typeof error,
            });
        }
        catch (auditError) {
            console.error('Failed to audit invitation role authority error:', auditError);
        }
    }
    async loadAdminUsers() {
        const config = getConfig();
        try {
            const data = await config.readFile(config.adminUsersFilePath);
            return JSON.parse(data);
        }
        catch {
            return [];
        }
    }
}
export const invitationService = new InvitationService();
export async function createInvitation(serverAuthContext, options) {
    return invitationService.createInvitation(serverAuthContext, options);
}
export async function acceptInvitation(data) {
    return invitationService.acceptInvitation(data);
}
export async function getInvitation(token) {
    return invitationService.getInvitation(token);
}
