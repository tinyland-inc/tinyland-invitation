/**
 * Comprehensive tests for @tinyland-inc/tinyland-invitation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { configure, getConfig, resetConfig } from '../src/config.js';
import { InvitationService } from '../src/service.js';
import type {
  InvitationConfig,
  AdminInvite,
  AdminUser,
  InvitationCreateOptions,
} from '../src/index.js';

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function createMocks() {
  return {
    readFile: vi.fn<(path: string) => Promise<string>>(),
    writeFile: vi.fn<(path: string, data: string) => Promise<void>>().mockResolvedValue(undefined),
    generateId: vi.fn(() => 'test-id-123'),
    hashPassword: vi.fn(async (pw: string, _rounds: number) => `hashed:${pw}`),
    generateTotpSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    generateKeyUri: vi.fn(
      (account: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${account}?secret=${secret}`,
    ),
    generateQrCode: vi.fn(async () => 'data:image/png;base64,qrcode'),
    auditLog: vi.fn<(eventType: string, data: Record<string, unknown>) => Promise<void>>().mockResolvedValue(undefined),
  };
}

type Mocks = ReturnType<typeof createMocks>;

function buildConfig(mocks: Mocks): InvitationConfig {
  return {
    readFile: mocks.readFile,
    writeFile: mocks.writeFile,
    invitesFilePath: '/tmp/invites.json',
    adminUsersFilePath: '/tmp/admin-users.json',
    generateId: mocks.generateId,
    hashPassword: mocks.hashPassword,
    generateTotpSecret: mocks.generateTotpSecret,
    generateKeyUri: mocks.generateKeyUri,
    generateQrCode: mocks.generateQrCode,
    authConfig: {
      invitation: { defaultExpiryHours: 48 },
      password: { bcryptRounds: 10 },
    },
    auditLog: mocks.auditLog,
    publicUrl: 'http://localhost:9080',
  };
}

/** Helper to build a valid, non-expired invite stored on disk */
function makeInvite(overrides: Partial<AdminInvite> = {}): AdminInvite {
  const future = new Date();
  future.setHours(future.getHours() + 24);
  return {
    id: 'inv-1',
    token: 'abc123',
    role: 'admin',
    createdBy: 'root',
    createdByHandle: 'root',
    createdAt: new Date().toISOString(),
    expiresAt: future.toISOString(),
    temporaryTotpSecret: 'JBSWY3DPEHPK3PXP',
    isActive: true,
    ...overrides,
  };
}

function makeExpiredInvite(overrides: Partial<AdminInvite> = {}): AdminInvite {
  const past = new Date();
  past.setHours(past.getHours() - 1);
  return makeInvite({ expiresAt: past.toISOString(), ...overrides });
}

function makeUsedInvite(overrides: Partial<AdminInvite> = {}): AdminInvite {
  return makeInvite({ usedAt: new Date().toISOString(), usedBy: 'user-1', ...overrides });
}

/** Standard create options */
const defaultCreateOptions: InvitationCreateOptions = {
  role: 'editor',
  createdBy: 'admin-1',
  createdByHandle: 'admin-handle',
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('tinyland-invitation', () => {
  let mocks: Mocks;

  beforeEach(() => {
    resetConfig();
    mocks = createMocks();
    // Default: invites file does not exist (start fresh)
    mocks.readFile.mockRejectedValue(new Error('not found'));
    configure(buildConfig(mocks));
  });

  afterEach(() => {
    resetConfig();
  });

  // -----------------------------------------------------------------------
  // configure / getConfig / resetConfig
  // -----------------------------------------------------------------------

  describe('configure / getConfig / resetConfig', () => {
    it('throws before configure is called', () => {
      resetConfig();
      expect(() => getConfig()).toThrow('tinyland-invitation is not configured');
    });

    it('returns config after configure is called', () => {
      resetConfig();
      const config = buildConfig(mocks);
      configure(config);
      expect(getConfig()).toBe(config);
    });

    it('resetConfig clears the configuration', () => {
      expect(() => getConfig()).not.toThrow();
      resetConfig();
      expect(() => getConfig()).toThrow();
    });

    it('configure can be called multiple times to replace config', () => {
      const config1 = buildConfig(mocks);
      const config2 = buildConfig(mocks);
      configure(config1);
      expect(getConfig()).toBe(config1);
      configure(config2);
      expect(getConfig()).toBe(config2);
    });
  });

  // -----------------------------------------------------------------------
  // createInvitation
  // -----------------------------------------------------------------------

  describe('createInvitation', () => {
    it('successfully creates an invitation with default expiry', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(result.success).toBe(true);
      expect(result.invitation).toBeDefined();
      expect(result.invitation!.role).toBe('editor');
      expect(result.invitation!.createdBy).toBe('admin-1');
      expect(result.invitation!.createdByHandle).toBe('admin-handle');
      expect(result.invitation!.isActive).toBe(true);
    });

    it('uses default expiry hours from authConfig', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      const expiresAt = new Date(result.invitation!.expiresAt);
      const now = new Date();
      const hoursFromNow = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      // Should be approximately 48 hours (default)
      expect(hoursFromNow).toBeGreaterThan(47);
      expect(hoursFromNow).toBeLessThanOrEqual(48.1);
    });

    it('respects custom expiresInHours', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation({
        ...defaultCreateOptions,
        expiresInHours: 72,
      });

      const expiresAt = new Date(result.invitation!.expiresAt);
      const now = new Date();
      const hoursFromNow = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      expect(hoursFromNow).toBeGreaterThan(71);
      expect(hoursFromNow).toBeLessThanOrEqual(72.1);
    });

    it('generates a 64-character hex token', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      const token = result.invitation!.token;
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generates a TOTP secret via DI', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(mocks.generateTotpSecret).toHaveBeenCalled();
      expect(result.totpSecret).toBe('JBSWY3DPEHPK3PXP');
      expect(result.invitation!.temporaryTotpSecret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('generates a QR code via DI', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(mocks.generateQrCode).toHaveBeenCalled();
      expect(result.qrCode).toBe('data:image/png;base64,qrcode');
    });

    it('builds invite URL from publicUrl config', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(result.inviteUrl).toContain('http://localhost:9080/admin/accept-invite?token=');
      expect(result.inviteUrl).toContain(result.invitation!.token);
    });

    it('calls generateKeyUri with correct arguments when handle is provided', async () => {
      const service = new InvitationService();
      await service.createInvitation({ ...defaultCreateOptions, handle: 'alice' });

      expect(mocks.generateKeyUri).toHaveBeenCalledWith(
        'alice',
        'Tinyland.dev (Invite)',
        'JBSWY3DPEHPK3PXP',
      );
    });

    it('uses fallback account name when handle is not provided', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);

      expect(mocks.generateKeyUri).toHaveBeenCalledWith(
        expect.stringMatching(/^invite-/),
        'Tinyland.dev (Invite)',
        'JBSWY3DPEHPK3PXP',
      );
    });

    it('calls auditLog with INVITATION_CREATED', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);

      expect(mocks.auditLog).toHaveBeenCalledWith('INVITATION_CREATED', {
        invitationId: 'test-id-123',
        handle: undefined,
        role: 'editor',
        createdBy: 'admin-1',
      });
    });

    it('calls generateId via DI', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);
      expect(mocks.generateId).toHaveBeenCalled();
    });

    it('saves invitations to file after creation', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);

      expect(mocks.writeFile).toHaveBeenCalledWith(
        '/tmp/invites.json',
        expect.any(String),
      );
    });

    it('returns error when an exception occurs during creation', async () => {
      mocks.generateQrCode.mockRejectedValueOnce(new Error('QR gen failed'));
      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to create invitation');
    });

    it('uses createdBy as createdByHandle when createdByHandle is empty', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation({
        ...defaultCreateOptions,
        createdByHandle: '',
      });

      expect(result.invitation!.createdByHandle).toBe('admin-1');
    });

    it('sets expiresInHours to 0 when explicitly passed as 0 (uses config default)', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation({
        ...defaultCreateOptions,
        expiresInHours: 0,
      });

      // 0 is falsy with ||, but with ?? it should stay 0; our implementation uses ??
      // so 0 should be kept as 0
      const expiresAt = new Date(result.invitation!.expiresAt);
      const now = new Date();
      const hoursFromNow = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      // With ?? operator, 0 is respected so expiry should be ~0 hours from now
      expect(hoursFromNow).toBeLessThan(1);
    });

    it('generates unique tokens for multiple invitations', async () => {
      const service = new InvitationService();
      const r1 = await service.createInvitation(defaultCreateOptions);
      const r2 = await service.createInvitation(defaultCreateOptions);

      expect(r1.invitation!.token).not.toBe(r2.invitation!.token);
    });
  });

  // -----------------------------------------------------------------------
  // getInvitation
  // -----------------------------------------------------------------------

  describe('getInvitation', () => {
    it('returns a valid invitation by token', async () => {
      const invite = makeInvite({ token: 'valid-token' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.getInvitation('valid-token');

      expect(result).not.toBeNull();
      expect(result!.token).toBe('valid-token');
    });

    it('returns null for an expired invitation', async () => {
      const invite = makeExpiredInvite({ token: 'expired-token' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      // Note: expired invites get cleaned up during init
      const result = await service.getInvitation('expired-token');
      expect(result).toBeNull();
    });

    it('returns null for a used invitation', async () => {
      const invite = makeUsedInvite({ token: 'used-token' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      // Used invites get cleaned up during init
      const result = await service.getInvitation('used-token');
      expect(result).toBeNull();
    });

    it('returns null for a nonexistent token', async () => {
      const service = new InvitationService();
      const result = await service.getInvitation('does-not-exist');
      expect(result).toBeNull();
    });

    it('returns null for an invitation that expired one second ago', async () => {
      const justPast = new Date();
      justPast.setSeconds(justPast.getSeconds() - 1);
      const invite = makeInvite({ token: 'edge-token', expiresAt: justPast.toISOString() });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.getInvitation('edge-token');
      expect(result).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // acceptInvitation
  // -----------------------------------------------------------------------

  describe('acceptInvitation', () => {
    let validToken: string;

    beforeEach(async () => {
      // Create a valid invite in the service
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);
      validToken = created.invitation!.token;

      // Make users file return empty
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });
    });

    it('successfully accepts a valid invitation', async () => {
      // Need a fresh service that will load the invite from file
      // Instead, use the same service that created the invite
      const service = new InvitationService();
      // Create within this service instance
      const created = await service.createInvitation(defaultCreateOptions);
      const token = created.invitation!.token;

      // Now set up readFile to return empty users
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const result = await service.acceptInvitation({
        token,
        handle: 'newuser',
        password: 'securepassword',
      });

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user!.handle).toBe('newuser');
      expect(result.user!.username).toBe('newuser');
      expect(result.userId).toBe('test-id-123');
      expect(result.needsOnboarding).toBe(true);
    });

    it('creates user with correct fields', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'alice',
        password: 'password123',
      });

      const user = result.user!;
      expect(user.email).toBe('');
      expect(user.role).toBe('editor');
      expect(user.totpEnabled).toBe(false);
      expect(user.totpSecretId).toBeUndefined();
      expect(user.isActive).toBe(true);
      expect(user.needsOnboarding).toBe(true);
      expect(user.onboardingStep).toBe(0);
      expect(user.firstLogin).toBe(true);
      expect(user.passwordHash).toBe('hashed:password123');
    });

    it('calls hashPassword with correct rounds from authConfig', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'bob',
        password: 'mypassword',
      });

      expect(mocks.hashPassword).toHaveBeenCalledWith('mypassword', 10);
    });

    it('marks invitation as used after acceptance', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);
      const token = created.invitation!.token;

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      await service.acceptInvitation({ token, handle: 'user1', password: 'pass' });

      // The invitation should now be used and not retrievable
      const after = await service.getInvitation(token);
      expect(after).toBeNull();
    });

    it('calls auditLog with INVITATION_ACCEPTED and USER_CREATED', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      mocks.auditLog.mockClear();

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'charlie',
        password: 'pass',
      });

      expect(mocks.auditLog).toHaveBeenCalledWith('INVITATION_ACCEPTED', expect.objectContaining({
        handle: 'charlie',
        role: 'editor',
      }));
      expect(mocks.auditLog).toHaveBeenCalledWith('USER_CREATED', expect.objectContaining({
        handle: 'charlie',
        role: 'editor',
        createdVia: 'invitation',
      }));
    });

    it('returns tempTotpSecret from the invitation', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'dana',
        password: 'pass',
      });

      expect(result.tempTotpSecret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('returns error for invalid token', async () => {
      const service = new InvitationService();
      const result = await service.acceptInvitation({
        token: 'nonexistent-token',
        handle: 'user',
        password: 'pass',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid or expired invitation');
    });

    it('returns error for expired token', async () => {
      const invite = makeExpiredInvite({ token: 'expired-for-accept' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.acceptInvitation({
        token: 'expired-for-accept',
        handle: 'user',
        password: 'pass',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid or expired invitation');
    });

    it('returns error for duplicate handle', async () => {
      const existingUser: AdminUser = {
        id: 'u-1',
        username: 'existing',
        handle: 'existing',
        email: '',
        passwordHash: 'hashed',
        role: 'admin',
        totpEnabled: false,
        isActive: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([existingUser]);
        throw new Error('not found');
      });

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'existing',
        password: 'pass',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Handle already taken');
    });

    it('writes new user to admin users file', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'frank',
        password: 'pass',
      });

      expect(mocks.writeFile).toHaveBeenCalledWith(
        '/tmp/admin-users.json',
        expect.stringContaining('"handle": "frank"'),
      );
    });

    it('returns error when an exception occurs', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });
      mocks.hashPassword.mockRejectedValueOnce(new Error('hash failure'));

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'eve',
        password: 'pass',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to accept invitation');
    });
  });

  // -----------------------------------------------------------------------
  // listPendingInvitations
  // -----------------------------------------------------------------------

  describe('listPendingInvitations', () => {
    it('returns only active, non-expired, non-used invitations', async () => {
      const valid = makeInvite({ token: 'valid', id: 'v1' });
      const expired = makeExpiredInvite({ token: 'expired', id: 'v2' });
      const used = makeUsedInvite({ token: 'used', id: 'v3' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([valid, expired, used]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();

      expect(pending).toHaveLength(1);
      expect(pending[0].token).toBe('valid');
    });

    it('returns empty array when there are no invitations', async () => {
      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('filters expired invitations', async () => {
      const e1 = makeExpiredInvite({ token: 'e1' });
      const e2 = makeExpiredInvite({ token: 'e2' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([e1, e2]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(0);
    });

    it('filters used invitations', async () => {
      const u1 = makeUsedInvite({ token: 'u1' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([u1]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(0);
    });

    it('returns multiple valid invitations', async () => {
      const v1 = makeInvite({ token: 'v1', id: 'id1' });
      const v2 = makeInvite({ token: 'v2', id: 'id2' });
      const v3 = makeInvite({ token: 'v3', id: 'id3' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([v1, v2, v3]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(3);
    });
  });

  // -----------------------------------------------------------------------
  // revokeInvitation
  // -----------------------------------------------------------------------

  describe('revokeInvitation', () => {
    it('successfully revokes an existing invitation', async () => {
      const invite = makeInvite({ token: 'to-revoke' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.revokeInvitation('to-revoke', 'admin-1');
      expect(result).toBe(true);
    });

    it('returns false for nonexistent invitation', async () => {
      const service = new InvitationService();
      const result = await service.revokeInvitation('nonexistent', 'admin-1');
      expect(result).toBe(false);
    });

    it('calls auditLog with INVITATION_REVOKED', async () => {
      const invite = makeInvite({ token: 'to-revoke-audit', id: 'inv-audit' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      mocks.auditLog.mockClear();
      await service.revokeInvitation('to-revoke-audit', 'admin-2');

      expect(mocks.auditLog).toHaveBeenCalledWith('INVITATION_REVOKED', {
        invitationId: 'inv-audit',
        action: 'revoked',
        revokedBy: 'admin-2',
      });
    });

    it('saves invitations after revocation', async () => {
      const invite = makeInvite({ token: 'to-revoke-save' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      mocks.writeFile.mockClear();
      await service.revokeInvitation('to-revoke-save', 'admin-1');

      expect(mocks.writeFile).toHaveBeenCalledWith('/tmp/invites.json', expect.any(String));
    });

    it('removes the invitation so it cannot be retrieved afterward', async () => {
      const invite = makeInvite({ token: 'to-revoke-gone' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      await service.revokeInvitation('to-revoke-gone', 'admin-1');

      const result = await service.getInvitation('to-revoke-gone');
      expect(result).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // extendInvitation
  // -----------------------------------------------------------------------

  describe('extendInvitation', () => {
    it('extends the expiry of a valid invitation', async () => {
      const invite = makeInvite({ token: 'to-extend' });
      const originalExpiry = new Date(invite.expiresAt).getTime();

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.extendInvitation('to-extend', 24);
      expect(result).toBe(true);

      // Verify the invite is still retrievable with updated expiry
      const updated = await service.getInvitation('to-extend');
      expect(updated).not.toBeNull();
      const newExpiry = new Date(updated!.expiresAt).getTime();
      expect(newExpiry).toBeGreaterThan(originalExpiry);
      // Should be extended by approximately 24 hours
      const diffHours = (newExpiry - originalExpiry) / (1000 * 60 * 60);
      expect(diffHours).toBeCloseTo(24, 0);
    });

    it('returns false for a used invitation', async () => {
      const invite = makeUsedInvite({ token: 'used-extend' });
      // Used invites are cleaned up during init, so we need to add it differently
      // Actually, the service cleans up used invites on init. So it won't be in the map.
      // Let's test with a service that already has the invite in its map
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);
      const token = created.invitation!.token;

      // Manually mark as used via accept
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });
      await service.acceptInvitation({ token, handle: 'extenduser', password: 'pass' });

      // Now try to extend
      const result = await service.extendInvitation(token, 24);
      expect(result).toBe(false);
    });

    it('returns false for nonexistent invitation', async () => {
      const service = new InvitationService();
      const result = await service.extendInvitation('nonexistent', 24);
      expect(result).toBe(false);
    });

    it('saves invitations after extending', async () => {
      const invite = makeInvite({ token: 'to-extend-save' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      mocks.writeFile.mockClear();
      await service.extendInvitation('to-extend-save', 12);

      expect(mocks.writeFile).toHaveBeenCalledWith('/tmp/invites.json', expect.any(String));
    });

    it('can extend by fractional hours', async () => {
      const invite = makeInvite({ token: 'fractional' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([invite]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.extendInvitation('fractional', 0.5);
      expect(result).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // getStatistics
  // -----------------------------------------------------------------------

  describe('getStatistics', () => {
    it('returns correct counts for mixed invitation states', async () => {
      const service = new InvitationService();

      // Create 3 invitations
      await service.createInvitation(defaultCreateOptions);
      await service.createInvitation(defaultCreateOptions);
      const third = await service.createInvitation(defaultCreateOptions);

      // Accept one
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });
      await service.acceptInvitation({
        token: third.invitation!.token,
        handle: 'statsuser',
        password: 'pass',
      });

      const stats = await service.getStatistics();
      // 3 total: 2 pending, 0 expired, 1 used
      expect(stats.total).toBe(3);
      expect(stats.pending).toBe(2);
      expect(stats.expired).toBe(0);
      expect(stats.used).toBe(1);
    });

    it('returns zeros when no invitations exist', async () => {
      const service = new InvitationService();
      const stats = await service.getStatistics();

      expect(stats.total).toBe(0);
      expect(stats.pending).toBe(0);
      expect(stats.expired).toBe(0);
      expect(stats.used).toBe(0);
    });

    it('counts expired invitations correctly', async () => {
      const valid = makeInvite({ token: 'stat-valid', id: 's1' });
      const expired1 = makeExpiredInvite({ token: 'stat-exp1', id: 's2' });
      const expired2 = makeExpiredInvite({ token: 'stat-exp2', id: 's3' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([valid, expired1, expired2]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      // Note: cleanupExpired removes expired entries during init
      const stats = await service.getStatistics();
      // After cleanup, only 'valid' remains
      expect(stats.total).toBe(1);
      expect(stats.pending).toBe(1);
      expect(stats.expired).toBe(0); // cleaned up
      expect(stats.used).toBe(0);
    });

    it('counts used invitations correctly', async () => {
      const service = new InvitationService();
      const c1 = await service.createInvitation(defaultCreateOptions);
      const c2 = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      // Use a different handle for each
      let handleCounter = 0;
      mocks.generateId.mockImplementation(() => `id-${++handleCounter}`);

      await service.acceptInvitation({
        token: c1.invitation!.token,
        handle: 'user-a',
        password: 'pass',
      });
      await service.acceptInvitation({
        token: c2.invitation!.token,
        handle: 'user-b',
        password: 'pass',
      });

      const stats = await service.getStatistics();
      expect(stats.used).toBe(2);
    });
  });

  // -----------------------------------------------------------------------
  // Lazy initialization
  // -----------------------------------------------------------------------

  describe('lazy initialization', () => {
    it('calls loadInvitations on first operation', async () => {
      const service = new InvitationService();
      await service.listPendingInvitations();

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('does not reload invitations on subsequent operations', async () => {
      const service = new InvitationService();
      await service.listPendingInvitations();
      const callCount = mocks.readFile.mock.calls.filter(
        (c) => c[0] === '/tmp/invites.json',
      ).length;

      await service.listPendingInvitations();
      const newCallCount = mocks.readFile.mock.calls.filter(
        (c) => c[0] === '/tmp/invites.json',
      ).length;

      expect(newCallCount).toBe(callCount);
    });

    it('initializes on getInvitation call', async () => {
      const service = new InvitationService();
      await service.getInvitation('any-token');

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('initializes on createInvitation call', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('initializes on revokeInvitation call', async () => {
      const service = new InvitationService();
      await service.revokeInvitation('token', 'admin');

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('initializes on extendInvitation call', async () => {
      const service = new InvitationService();
      await service.extendInvitation('token', 1);

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('initializes on getStatistics call', async () => {
      const service = new InvitationService();
      await service.getStatistics();

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('initializes on acceptInvitation call', async () => {
      const service = new InvitationService();
      await service.acceptInvitation({ token: 'x', handle: 'y', password: 'z' });

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });
  });

  // -----------------------------------------------------------------------
  // cleanupExpired
  // -----------------------------------------------------------------------

  describe('cleanupExpired', () => {
    it('removes expired invitations on init', async () => {
      const valid = makeInvite({ token: 'keep-me', id: 'k1' });
      const expired = makeExpiredInvite({ token: 'remove-me', id: 'r1' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([valid, expired]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();

      expect(pending).toHaveLength(1);
      expect(pending[0].token).toBe('keep-me');
    });

    it('removes used invitations on init', async () => {
      const valid = makeInvite({ token: 'keep-valid', id: 'kv1' });
      const used = makeUsedInvite({ token: 'remove-used', id: 'ru1' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([valid, used]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();

      expect(pending).toHaveLength(1);
      expect(pending[0].token).toBe('keep-valid');
    });

    it('saves to file when cleanup occurs', async () => {
      const expired = makeExpiredInvite({ token: 'cleanup-save' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([expired]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      mocks.writeFile.mockClear();
      await service.listPendingInvitations(); // triggers init

      expect(mocks.writeFile).toHaveBeenCalledWith('/tmp/invites.json', expect.any(String));
    });

    it('does not save when nothing to clean up', async () => {
      const valid = makeInvite({ token: 'all-valid' });

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([valid]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      mocks.writeFile.mockClear();
      await service.listPendingInvitations(); // triggers init

      // writeFile should NOT have been called by cleanup (no changes needed)
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // File I/O
  // -----------------------------------------------------------------------

  describe('file I/O', () => {
    it('reads invites from the configured path', async () => {
      const service = new InvitationService();
      await service.listPendingInvitations();

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('writes invitations as serialized JSON', async () => {
      const service = new InvitationService();
      await service.createInvitation(defaultCreateOptions);

      const writeCall = mocks.writeFile.mock.calls.find((c) => c[0] === '/tmp/invites.json');
      expect(writeCall).toBeDefined();

      const written = JSON.parse(writeCall![1]);
      expect(Array.isArray(written)).toBe(true);
      expect(written[0]).toHaveProperty('token');
      expect(written[0]).toHaveProperty('id');
    });

    it('handles readFile errors gracefully (starts fresh)', async () => {
      mocks.readFile.mockRejectedValue(new Error('ENOENT'));

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('reads admin users from the configured path during accept', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'iotest',
        password: 'pass',
      });

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/admin-users.json');
    });

    it('writes admin users to the configured path during accept', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'writetest',
        password: 'pass',
      });

      expect(mocks.writeFile).toHaveBeenCalledWith(
        '/tmp/admin-users.json',
        expect.any(String),
      );
    });

    it('handles missing admin users file gracefully', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      // readFile always throws (including for admin-users.json)
      mocks.readFile.mockRejectedValue(new Error('ENOENT'));

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'nousers',
        password: 'pass',
      });

      expect(result.success).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  describe('edge cases', () => {
    it('handles empty invitations file', async () => {
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('handles legacy format {invites: [...]}', async () => {
      const invite = makeInvite({ token: 'legacy-token' });
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify({ invites: [invite] });
        throw new Error('not found');
      });

      const service = new InvitationService();
      const result = await service.getInvitation('legacy-token');
      expect(result).not.toBeNull();
      expect(result!.token).toBe('legacy-token');
    });

    it('handles legacy format with empty invites array', async () => {
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify({ invites: [] });
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('handles legacy format with missing invites key', async () => {
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return JSON.stringify({ other: 'data' });
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('each new InvitationService instance has independent state', async () => {
      const service1 = new InvitationService();
      await service1.createInvitation(defaultCreateOptions);

      const service2 = new InvitationService();
      // service2 starts fresh (readFile throws not found)
      const pending = await service2.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('handles invalid JSON in invites file gracefully', async () => {
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/invites.json') return 'not valid json{{{';
        throw new Error('not found');
      });

      const service = new InvitationService();
      const pending = await service.listPendingInvitations();
      expect(pending).toEqual([]);
    });

    it('handles writeFile errors during create', async () => {
      mocks.writeFile.mockRejectedValueOnce(new Error('disk full'));

      const service = new InvitationService();
      const result = await service.createInvitation(defaultCreateOptions);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to create invitation');
    });

    it('preserves invitation data through save/load cycle', async () => {
      let savedData = '';
      mocks.writeFile.mockImplementation(async (_path: string, data: string) => {
        savedData = data;
      });

      const service = new InvitationService();
      const created = await service.createInvitation({
        ...defaultCreateOptions,
        handle: 'roundtrip',
      });

      // Verify saved data can be parsed back
      const parsed = JSON.parse(savedData);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].token).toBe(created.invitation!.token);
      expect(parsed[0].temporaryTotpSecret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('creates invitation with createdByHandle falling back to createdBy', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation({
        role: 'admin',
        createdBy: 'creator-id',
        createdByHandle: '',
      });

      expect(result.invitation!.createdByHandle).toBe('creator-id');
    });

    it('handles concurrent creates without data loss', async () => {
      const service = new InvitationService();

      const results = await Promise.all([
        service.createInvitation({ ...defaultCreateOptions, handle: 'user1' }),
        service.createInvitation({ ...defaultCreateOptions, handle: 'user2' }),
        service.createInvitation({ ...defaultCreateOptions, handle: 'user3' }),
      ]);

      expect(results.every((r) => r.success)).toBe(true);

      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(3);
    });

    it('handles the case where admin users file returns invalid JSON', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(defaultCreateOptions);

      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return 'not json';
        throw new Error('not found');
      });

      // This should fail because JSON.parse will throw, which gets caught
      // Actually, loadAdminUsers catches errors and returns []
      // But "not json" will throw in JSON.parse which IS caught by the catch
      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'badjson',
        password: 'pass',
      });

      // loadAdminUsers catches parse errors and returns [], so accept should succeed
      expect(result.success).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Convenience function exports
  // -----------------------------------------------------------------------

  describe('convenience functions', () => {
    it('createInvitation delegates to singleton', async () => {
      // We can only test this indirectly by importing the functions
      // and verifying they produce the same behavior
      const { createInvitation } = await import('../src/service.js');
      // The singleton shares the same config
      const result = await createInvitation(defaultCreateOptions);
      expect(result.success).toBe(true);
    });

    it('getInvitation delegates to singleton', async () => {
      const { getInvitation } = await import('../src/service.js');
      const result = await getInvitation('nonexistent');
      expect(result).toBeNull();
    });

    it('acceptInvitation delegates to singleton', async () => {
      const { acceptInvitation } = await import('../src/service.js');
      const result = await acceptInvitation({
        token: 'nonexistent',
        handle: 'user',
        password: 'pass',
      });
      expect(result.success).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Config validation
  // -----------------------------------------------------------------------

  describe('config validation', () => {
    it('service methods throw when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.listPendingInvitations()).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });

    it('createInvitation throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.createInvitation(defaultCreateOptions)).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });

    it('acceptInvitation throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(
        service.acceptInvitation({ token: 'x', handle: 'y', password: 'z' }),
      ).rejects.toThrow('tinyland-invitation is not configured');
    });

    it('getInvitation throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.getInvitation('token')).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });

    it('revokeInvitation throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.revokeInvitation('token', 'admin')).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });

    it('extendInvitation throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.extendInvitation('token', 24)).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });

    it('getStatistics throws when config is not set', async () => {
      resetConfig();
      const service = new InvitationService();

      await expect(service.getStatistics()).rejects.toThrow(
        'tinyland-invitation is not configured',
      );
    });
  });

  // -----------------------------------------------------------------------
  // Full workflow integration
  // -----------------------------------------------------------------------

  describe('full workflow', () => {
    it('create -> get -> accept -> verify used', async () => {
      const service = new InvitationService();

      // Step 1: Create
      const created = await service.createInvitation({
        role: 'moderator',
        createdBy: 'super-admin',
        createdByHandle: 'SuperAdmin',
        handle: 'newmod',
      });
      expect(created.success).toBe(true);
      const token = created.invitation!.token;

      // Step 2: Get
      const fetched = await service.getInvitation(token);
      expect(fetched).not.toBeNull();
      expect(fetched!.role).toBe('moderator');

      // Step 3: Accept
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });

      const accepted = await service.acceptInvitation({
        token,
        handle: 'newmod',
        password: 'strongpass!',
      });
      expect(accepted.success).toBe(true);
      expect(accepted.user!.role).toBe('moderator');
      expect(accepted.needsOnboarding).toBe(true);

      // Step 4: Verify used
      const afterAccept = await service.getInvitation(token);
      expect(afterAccept).toBeNull();
    });

    it('create -> revoke -> verify gone', async () => {
      const service = new InvitationService();

      const created = await service.createInvitation(defaultCreateOptions);
      const token = created.invitation!.token;

      // Verify exists
      const before = await service.getInvitation(token);
      expect(before).not.toBeNull();

      // Revoke
      const revoked = await service.revokeInvitation(token, 'admin');
      expect(revoked).toBe(true);

      // Verify gone
      const after = await service.getInvitation(token);
      expect(after).toBeNull();
    });

    it('create -> extend -> verify extended', async () => {
      const service = new InvitationService();

      const created = await service.createInvitation(defaultCreateOptions);
      const token = created.invitation!.token;
      const originalExpiry = new Date(created.invitation!.expiresAt);

      // Extend
      const extended = await service.extendInvitation(token, 48);
      expect(extended).toBe(true);

      // Verify
      const after = await service.getInvitation(token);
      expect(after).not.toBeNull();
      const newExpiry = new Date(after!.expiresAt);
      expect(newExpiry.getTime()).toBeGreaterThan(originalExpiry.getTime());
    });

    it('create multiple -> list pending -> verify count', async () => {
      const service = new InvitationService();

      await service.createInvitation(defaultCreateOptions);
      await service.createInvitation(defaultCreateOptions);
      await service.createInvitation(defaultCreateOptions);

      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(3);

      const stats = await service.getStatistics();
      expect(stats.total).toBe(3);
      expect(stats.pending).toBe(3);
    });
  });
});
