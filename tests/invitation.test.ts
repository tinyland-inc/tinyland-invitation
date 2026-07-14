



import { describe, it, expect, expectTypeOf, vi, beforeEach, afterEach } from 'vitest';
import { configure, getConfig, resetConfig } from '../src/config.js';
import { InvitationService } from '../src/service.js';
import {
  createInvitationRoleAuthority,
  InvitationError,
  SUPPORTED_RBAC_AUTHORITY_VERSION,
} from '../src/index.js';
import type {
  InvitationConfig,
  AdminInvite,
  AdminUser,
  InvitationCreateOptions,
  InvitationPrincipal,
} from '../src/index.js';


const DEFAULT_SERVER_AUTH_CONTEXT = Object.freeze({ sessionId: 'server-session-1' });
const DEFAULT_PRINCIPAL: InvitationPrincipal = Object.freeze({
  id: 'admin-1',
  role: 'super_admin',
  handle: 'admin-handle',
  isActive: true,
});




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
    resolveInvitationPrincipal: vi.fn<
      (serverAuthContext: unknown) => Promise<InvitationPrincipal | null | undefined>
    >(async (serverAuthContext: unknown) =>
      serverAuthContext === DEFAULT_SERVER_AUTH_CONTEXT ? DEFAULT_PRINCIPAL : null,
    ),
  };
}

type Mocks = ReturnType<typeof createMocks>;

const TEST_ROLE_RANKS = Object.freeze({
  super_admin: 100,
  admin: 90,
  moderator: 70,
  editor: 60,
  event_manager: 50,
  contributor: 40,
  member: 30,
  viewer: 10,
} as const);

function testCanManageRole(actorRole: string, targetRole: string): boolean {
  if (
    !Object.prototype.hasOwnProperty.call(TEST_ROLE_RANKS, actorRole) ||
    !Object.prototype.hasOwnProperty.call(TEST_ROLE_RANKS, targetRole)
  ) {
    return false;
  }

  return (
    TEST_ROLE_RANKS[actorRole as keyof typeof TEST_ROLE_RANKS] >
    TEST_ROLE_RANKS[targetRole as keyof typeof TEST_ROLE_RANKS]
  );
}

function createTestRoleAuthority() {
  return createInvitationRoleAuthority({
    version: SUPPORTED_RBAC_AUTHORITY_VERSION,
    canManageRole: testCanManageRole,
  });
}

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
    roleAuthority: createTestRoleAuthority(),
    resolveInvitationPrincipal: mocks.resolveInvitationPrincipal,
  };
}

function setResolvedPrincipal(
  mocks: Mocks,
  overrides: Partial<InvitationPrincipal>,
): InvitationPrincipal {
  const resolved = Object.freeze({ ...DEFAULT_PRINCIPAL, ...overrides });
  mocks.resolveInvitationPrincipal.mockResolvedValue(resolved);
  return resolved;
}

function installStatefulStorage(mocks: Mocks): Map<string, string> {
  const files = new Map<string, string>();
  mocks.readFile.mockImplementation(async (path: string) => {
    const data = files.get(path);
    if (data === undefined) {
      throw new Error(`ENOENT: ${path}`);
    }
    return data;
  });
  mocks.writeFile.mockImplementation(async (path: string, data: string) => {
    files.set(path, data);
  });
  return files;
}


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


const defaultCreateOptions: InvitationCreateOptions = {
  role: 'editor',
};





describe('tinyland-invitation', () => {
  let mocks: Mocks;

  beforeEach(() => {
    resetConfig();
    mocks = createMocks();
    
    mocks.readFile.mockRejectedValue(new Error('not found'));
    configure(buildConfig(mocks));
  });

  afterEach(() => {
    resetConfig();
  });

  
  
  

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

    it('rejects configuration without a principal resolver', () => {
      expect(() =>
        configure({
          ...buildConfig(mocks),
          resolveInvitationPrincipal: undefined,
        } as unknown as InvitationConfig),
      ).toThrow('resolveInvitationPrincipal must be configured');
    });
  });

  
  
  

  describe('createInvitation', () => {
    it('excludes actor identity and role from the public request type', () => {
      expectTypeOf<InvitationCreateOptions>().not.toHaveProperty('createdBy');
      expectTypeOf<InvitationCreateOptions>().not.toHaveProperty('createdByRole');
      expectTypeOf<InvitationCreateOptions>().not.toHaveProperty('createdByHandle');
      expectTypeOf<InvitationService['createInvitation']>()
        .parameters.toEqualTypeOf<[unknown, InvitationCreateOptions]>();
    });

    it('throws InvitationError when the narrowing hook denies an authority allow', async () => {
      const config = buildConfig(mocks);
      const canCreateInviteForRole = vi.fn<
        NonNullable<InvitationConfig['canCreateInviteForRole']>
      >(() => false);
      configure({ ...config, canCreateInviteForRole });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          ...defaultCreateOptions,
          role: 'editor',
        }),
      ).rejects.toThrow('Insufficient permissions to create invitation for this role');

      expect(canCreateInviteForRole).toHaveBeenCalledWith({
        principal: DEFAULT_PRINCIPAL,
        targetRole: 'editor',
      });
      const decision = canCreateInviteForRole.mock.calls[0]![0];
      expect(Object.isFrozen(decision)).toBe(true);
      expect(Object.isFrozen(decision.principal)).toBe(true);
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('creates the invitation when both authority and async hook allow', async () => {
      const config = buildConfig(mocks);
      const canCreateInviteForRole = vi.fn(async () => true);
      configure({ ...config, canCreateInviteForRole });

      const service = new InvitationService();
      const result = await service.createInvitation(
        DEFAULT_SERVER_AUTH_CONTEXT,
        defaultCreateOptions,
      );

      expect(result.success).toBe(true);
      expect(canCreateInviteForRole).toHaveBeenCalledWith({
        principal: DEFAULT_PRINCIPAL,
        targetRole: 'editor',
      });
    });

    it('applies the injected authority when no narrowing hook is configured', async () => {
      setResolvedPrincipal(mocks, { role: 'editor' });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          ...defaultCreateOptions,
          role: 'admin',
        }),
      ).rejects.toBeInstanceOf(InvitationError);

      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('allows creation when the authority says the creator strictly outranks the target', async () => {
      setResolvedPrincipal(mocks, { role: 'admin' });
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        ...defaultCreateOptions,
        role: 'editor',
      });

      expect(result.success).toBe(true);
      expect(result.invitation!.role).toBe('editor');
    });

    it('successfully creates an invitation with default expiry', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(result.success).toBe(true);
      expect(result.invitation).toBeDefined();
      expect(result.invitation!.role).toBe('editor');
      expect(result.invitation!.createdBy).toBe('admin-1');
      expect(result.invitation!.createdByHandle).toBe('admin-handle');
      expect(result.invitation!.isActive).toBe(true);
    });

    it('uses default expiry hours from authConfig', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      const expiresAt = new Date(result.invitation!.expiresAt);
      const now = new Date();
      const hoursFromNow = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      
      expect(hoursFromNow).toBeGreaterThan(47);
      expect(hoursFromNow).toBeLessThanOrEqual(48.1);
    });

    it('respects custom expiresInHours', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
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
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      const token = result.invitation!.token;
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('generates a TOTP secret via DI', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(mocks.generateTotpSecret).toHaveBeenCalled();
      expect(result.totpSecret).toBe('JBSWY3DPEHPK3PXP');
      expect(result.invitation!.temporaryTotpSecret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('generates a QR code via DI', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(mocks.generateQrCode).toHaveBeenCalled();
      expect(result.qrCode).toBe('data:image/png;base64,qrcode');
    });

    it('builds invite URL from publicUrl config', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(result.inviteUrl).toContain('http://localhost:9080/admin/accept-invite?token=');
      expect(result.inviteUrl).toContain(result.invitation!.token);
    });

    it('calls generateKeyUri with correct arguments when handle is provided', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, { ...defaultCreateOptions, handle: 'alice' });

      expect(mocks.generateKeyUri).toHaveBeenCalledWith(
        'alice',
        'Tinyland.dev (Invite)',
        'JBSWY3DPEHPK3PXP',
      );
    });

    it('uses fallback account name when handle is not provided', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(mocks.generateKeyUri).toHaveBeenCalledWith(
        expect.stringMatching(/^invite-/),
        'Tinyland.dev (Invite)',
        'JBSWY3DPEHPK3PXP',
      );
    });

    it('calls auditLog with INVITATION_CREATED', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(mocks.auditLog).toHaveBeenCalledWith('INVITATION_CREATED', {
        invitationId: 'test-id-123',
        handle: undefined,
        role: 'editor',
        createdBy: 'admin-1',
        createdByRole: 'super_admin',
        createdByHandle: 'admin-handle',
      });
    });

    it('calls generateId via DI', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      expect(mocks.generateId).toHaveBeenCalled();
    });

    it('saves invitations to file after creation', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(mocks.writeFile).toHaveBeenCalledWith(
        '/tmp/invites.json',
        expect.any(String),
      );
    });

    it('returns error when an exception occurs during creation', async () => {
      mocks.generateQrCode.mockRejectedValueOnce(new Error('QR gen failed'));
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to create invitation');
    });

    it('ignores forged runtime actor fields and uses only the resolved principal', async () => {
      const service = new InvitationService();
      const forgedRequest = {
        ...defaultCreateOptions,
        createdBy: 'forged-id',
        createdByRole: 'root',
        createdByHandle: 'forged-handle',
      } as InvitationCreateOptions;
      const result = await service.createInvitation(
        DEFAULT_SERVER_AUTH_CONTEXT,
        forgedRequest,
      );

      expect(result.invitation).toMatchObject({
        createdBy: DEFAULT_PRINCIPAL.id,
        createdByHandle: DEFAULT_PRINCIPAL.handle,
      });
      expect(mocks.resolveInvitationPrincipal).toHaveBeenCalledWith(
        DEFAULT_SERVER_AUTH_CONTEXT,
      );
      expect(JSON.stringify(mocks.auditLog.mock.calls)).not.toContain('forged');
    });

    it('sets expiresInHours to 0 when explicitly passed as 0 (uses config default)', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        ...defaultCreateOptions,
        expiresInHours: 0,
      });

      
      
      const expiresAt = new Date(result.invitation!.expiresAt);
      const now = new Date();
      const hoursFromNow = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60);
      
      expect(hoursFromNow).toBeLessThan(1);
    });

    it('generates unique tokens for multiple invitations', async () => {
      const service = new InvitationService();
      const r1 = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const r2 = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(r1.invitation!.token).not.toBe(r2.invitation!.token);
    });
  });

  describe('principal binding (TIN-2835)', () => {
    it('denies missing and deleted principals before storage initialization', async () => {
      for (const resolved of [null, undefined]) {
        mocks.resolveInvitationPrincipal.mockResolvedValueOnce(resolved);
        const service = new InvitationService();

        await expect(
          service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions),
        ).rejects.toMatchObject({ name: 'InvitationError', code: 'forbidden' });
      }

      expect(mocks.readFile).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('denies an inactive principal before role policy and storage writes', async () => {
      setResolvedPrincipal(mocks, { isActive: false });
      const canManageRole = vi.fn(() => true);
      configure({
        ...buildConfig(mocks),
        roleAuthority: createInvitationRoleAuthority({
          version: SUPPORTED_RBAC_AUTHORITY_VERSION,
          canManageRole,
        }),
      });

      await expect(
        new InvitationService().createInvitation(
          DEFAULT_SERVER_AUTH_CONTEXT,
          defaultCreateOptions,
        ),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(canManageRole).not.toHaveBeenCalled();
      expect(mocks.readFile).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it.each([
      ['missing role', { id: 'admin-1', handle: 'admin', isActive: true }],
      [
        'extra field',
        {
          id: 'admin-1',
          role: 'super_admin',
          handle: 'admin',
          isActive: true,
          email: 'admin@example.com',
        },
      ],
      [
        'non-boolean active state',
        { id: 'admin-1', role: 'super_admin', handle: 'admin', isActive: 'true' },
      ],
      [
        'empty identity',
        { id: '', role: 'super_admin', handle: 'admin', isActive: true },
      ],
      [
        'accessor-backed identity',
        Object.defineProperties({}, {
          id: { get: () => 'admin-1', enumerable: true },
          role: { get: () => 'super_admin', enumerable: true },
          handle: { get: () => 'admin', enumerable: true },
          isActive: { get: () => true, enumerable: true },
        }),
      ],
    ])('denies malformed exact-shape principal: %s', async (_name, malformed) => {
      mocks.resolveInvitationPrincipal.mockResolvedValueOnce(
        malformed as InvitationPrincipal,
      );

      await expect(
        new InvitationService().createInvitation(
          DEFAULT_SERVER_AUTH_CONTEXT,
          defaultCreateOptions,
        ),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.readFile).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('audits a resolver exception without request or context identity and denies', async () => {
      mocks.resolveInvitationPrincipal.mockRejectedValueOnce(
        new TypeError('session store unavailable'),
      );

      await expect(
        new InvitationService().createInvitation(
          DEFAULT_SERVER_AUTH_CONTEXT,
          defaultCreateOptions,
        ),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.auditLog).toHaveBeenCalledWith(
        'INVITATION_PRINCIPAL_RESOLUTION_ERROR',
        { reason: 'resolver_error', errorType: 'TypeError' },
      );
      expect(JSON.stringify(mocks.auditLog.mock.calls)).not.toContain('server-session-1');
      expect(mocks.readFile).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('reloads the current principal role on every mint attempt', async () => {
      mocks.resolveInvitationPrincipal
        .mockResolvedValueOnce({ ...DEFAULT_PRINCIPAL, role: 'admin' })
        .mockResolvedValueOnce({ ...DEFAULT_PRINCIPAL, role: 'viewer' });
      const service = new InvitationService();

      const allowed = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        role: 'editor',
      });
      expect(allowed.success).toBe(true);
      const writesAfterAllow = mocks.writeFile.mock.calls.length;

      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, { role: 'editor' }),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.resolveInvitationPrincipal).toHaveBeenCalledTimes(2);
      expect(mocks.writeFile).toHaveBeenCalledTimes(writesAfterAllow);
    });
  });

  //
  // Role-authority gate (TIN-1607 R3)
  //

  describe('role-authority gate (TIN-1607, TIN-2822)', () => {
    it('authority: creator strictly outranking target is allowed', async () => {
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        role: 'editor',
      });
      expect(result.success).toBe(true);
      expect(result.invitation!.role).toBe('editor');
    });

    it('authority: equal rank is denied (strict outranking required)', async () => {
      setResolvedPrincipal(mocks, { id: 'peer', role: 'admin', handle: 'peer' });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'admin',
        }),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('authority: lower rank creating a higher role is denied', async () => {
      setResolvedPrincipal(mocks, { id: 'mod', role: 'moderator', handle: 'mod' });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'super_admin',
        }),
      ).rejects.toThrow(InvitationError);
    });

    it('routes an unknown resolved role through the auth-owned adapter and denies', async () => {
      setResolvedPrincipal(mocks, { id: 'x', role: 'wizard', handle: 'x' });
      const canManageRole = vi.fn(testCanManageRole);
      configure({
        ...buildConfig(mocks),
        roleAuthority: createInvitationRoleAuthority({
          version: SUPPORTED_RBAC_AUTHORITY_VERSION,
          canManageRole,
        }),
      });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'editor',
        }),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(canManageRole).toHaveBeenCalledWith('wizard', 'editor');
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('authority is never blindly permissive: a viewer cannot mint an admin invite', async () => {
      setResolvedPrincipal(mocks, { id: 'v', role: 'viewer', handle: 'v' });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'admin',
        }),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('an allowing hook cannot elevate a role pair denied by the authority', async () => {
      setResolvedPrincipal(mocks, { id: 'v', role: 'viewer', handle: 'v' });
      const config = buildConfig(mocks);
      const canCreateInviteForRole = vi.fn(() => true);
      configure({ ...config, canCreateInviteForRole });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'admin',
        }),
      ).rejects.toBeInstanceOf(InvitationError);

      expect(canCreateInviteForRole).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('a denying hook blocks an otherwise-allowed authority decision', async () => {
      const config = buildConfig(mocks);
      const canCreateInviteForRole = vi.fn(() => false);
      configure({ ...config, canCreateInviteForRole });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'editor',
        }),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('missing authority is rejected during configuration', () => {
      const canCreateInviteForRole = vi.fn(() => true);
      expect(() =>
        configure({
          ...buildConfig(mocks),
          roleAuthority: undefined,
          canCreateInviteForRole,
        } as unknown as InvitationConfig),
      ).toThrow('roleAuthority must be created by this package instance');

      expect(canCreateInviteForRole).not.toHaveBeenCalled();
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('a throwing narrowing hook denies with the typed forbidden error', async () => {
      configure({
        ...buildConfig(mocks),
        canCreateInviteForRole: () => {
          throw new Error('policy unavailable');
        },
      });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions),
      ).rejects.toMatchObject({ name: 'InvitationError', code: 'forbidden' });
      expect(mocks.auditLog).toHaveBeenCalledWith(
        'INVITATION_ROLE_AUTHORITY_ERROR',
        expect.objectContaining({
          reason: 'narrowing_hook_error',
          errorType: 'Error',
        }),
      );
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('an asynchronously rejected narrowing hook is audited and denied', async () => {
      configure({
        ...buildConfig(mocks),
        canCreateInviteForRole: async () => {
          throw new TypeError('policy unavailable');
        },
      });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.auditLog).toHaveBeenCalledWith(
        'INVITATION_ROLE_AUTHORITY_ERROR',
        expect.objectContaining({
          reason: 'narrowing_hook_error',
          errorType: 'TypeError',
        }),
      );
    });

    it('a truthy non-boolean narrowing result denies', async () => {
      configure({
        ...buildConfig(mocks),
        canCreateInviteForRole: (() => 'yes') as unknown as NonNullable<
          InvitationConfig['canCreateInviteForRole']
        >,
      });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('a throwing authority is audited and denied', async () => {
      const roleAuthority = createInvitationRoleAuthority({
        version: SUPPORTED_RBAC_AUTHORITY_VERSION,
        canManageRole: async () => {
          throw new RangeError('authority unavailable');
        },
      });
      configure({ ...buildConfig(mocks), roleAuthority });

      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions),
      ).rejects.toBeInstanceOf(InvitationError);
      expect(mocks.auditLog).toHaveBeenCalledWith(
        'INVITATION_ROLE_AUTHORITY_ERROR',
        expect.objectContaining({
          reason: 'authority_error',
          createdBy: DEFAULT_PRINCIPAL.id,
          createdByRole: DEFAULT_PRINCIPAL.role,
          createdByHandle: DEFAULT_PRINCIPAL.handle,
          errorType: 'RangeError',
        }),
      );
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });

    it('thrown InvitationError carries the forbidden code', async () => {
      setResolvedPrincipal(mocks, { id: 'v', role: 'viewer', handle: 'v' });
      const service = new InvitationService();
      await expect(
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
          role: 'admin',
        }),
      ).rejects.toMatchObject({ name: 'InvitationError', code: 'forbidden' });
    });
  });





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

  
  
  

  describe('acceptInvitation', () => {
    let files: Map<string, string>;

    beforeEach(() => {
      files = installStatefulStorage(mocks);
    });

    it('successfully accepts a valid invitation', async () => {
      
      
      const service = new InvitationService();
      
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

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
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'bob',
        password: 'mypassword',
      });

      expect(mocks.hashPassword).toHaveBeenCalledWith('mypassword', 10);
    });

    it('marks invitation as used after acceptance', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

      await service.acceptInvitation({ token, handle: 'user1', password: 'pass' });

      
      const after = await service.getInvitation(token);
      expect(after).toBeNull();
    });

    it('allows exactly one concurrent acceptance for one token', async () => {
      const creator = new InvitationService();
      const created = await creator.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;
      const services = Array.from({ length: 12 }, () => new InvitationService());

      await Promise.all(services.map((service) => service.getInvitation(token)));

      let markHashStarted!: () => void;
      const hashStarted = new Promise<void>((resolve) => {
        markHashStarted = resolve;
      });
      let releaseHash!: () => void;
      const hashGate = new Promise<void>((resolve) => {
        releaseHash = resolve;
      });
      mocks.hashPassword.mockImplementation(async (password: string) => {
        markHashStarted();
        await hashGate;
        return `hashed:${password}`;
      });

      const first = services[0].acceptInvitation({
        token,
        handle: 'contender-0',
        password: 'pass-0',
      });
      await hashStarted;

      const remaining = services.slice(1).map((service, index) =>
        service.acceptInvitation({
          token,
          handle: `contender-${index + 1}`,
          password: `pass-${index + 1}`,
        }),
      );
      releaseHash();

      const results = await Promise.all([first, ...remaining]);
      const successes = results.filter((result) => result.success);
      const failures = results.filter((result) => !result.success);
      const users = JSON.parse(files.get('/tmp/admin-users.json') ?? '[]') as AdminUser[];

      expect(successes).toHaveLength(1);
      expect(successes[0].user?.handle).toBe('contender-0');
      expect(failures).toHaveLength(11);
      expect(failures.every((result) => result.error === 'Invalid or expired invitation')).toBe(true);
      expect(users).toHaveLength(1);
      expect(users[0]).toMatchObject({ handle: 'contender-0', role: 'editor' });
      expect(mocks.hashPassword).toHaveBeenCalledTimes(1);
      expect(
        mocks.writeFile.mock.calls.filter(([path]) => path === '/tmp/admin-users.json'),
      ).toHaveLength(1);
    });

    it('re-reads used state after a stale service instance enters the token lock', async () => {
      const acceptingService = new InvitationService();
      const created = await acceptingService.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;
      const staleService = new InvitationService();

      expect(await staleService.getInvitation(token)).not.toBeNull();

      const accepted = await acceptingService.acceptInvitation({
        token,
        handle: 'first-handle',
        password: 'first-pass',
      });
      const replay = await staleService.acceptInvitation({
        token,
        handle: 'second-handle',
        password: 'second-pass',
      });
      const users = JSON.parse(files.get('/tmp/admin-users.json') ?? '[]') as AdminUser[];

      expect(accepted.success).toBe(true);
      expect(replay).toEqual({
        success: false,
        error: 'Invalid or expired invitation',
      });
      expect(users.map((user) => user.handle)).toEqual(['first-handle']);
      expect(mocks.hashPassword).toHaveBeenCalledTimes(1);
    });

    it('calls auditLog with INVITATION_ACCEPTED and USER_CREATED', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      files.set('/tmp/invites.json', JSON.stringify([invite]));

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
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      files.set('/tmp/admin-users.json', JSON.stringify([existingUser]));

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
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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

    it('keeps the token consumed when user creation fails after the claim', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

      mocks.hashPassword.mockRejectedValueOnce(new Error('hash failure'));

      const result = await service.acceptInvitation({
        token,
        handle: 'eve',
        password: 'pass',
      });
      const retry = await service.acceptInvitation({
        token,
        handle: 'eve-retry',
        password: 'pass',
      });
      const persistedInvites = JSON.parse(files.get('/tmp/invites.json') ?? '[]') as AdminInvite[];

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to accept invitation');
      expect(retry).toEqual({
        success: false,
        error: 'Invalid or expired invitation',
      });
      expect(persistedInvites).toHaveLength(1);
      expect(persistedInvites[0].usedAt).toEqual(expect.any(String));
      expect(persistedInvites[0].usedBy).toEqual(expect.any(String));
      expect(files.has('/tmp/admin-users.json')).toBe(false);
    });

    it('fails closed in-process when the token claim cannot be persisted', async () => {
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

      mocks.writeFile.mockRejectedValueOnce(new Error('claim write failed'));

      const result = await service.acceptInvitation({
        token,
        handle: 'claim-failure',
        password: 'pass',
      });
      const retry = await service.acceptInvitation({
        token,
        handle: 'claim-failure-retry',
        password: 'pass',
      });

      expect(result).toEqual({
        success: false,
        error: 'Failed to accept invitation',
      });
      expect(retry).toEqual({
        success: false,
        error: 'Invalid or expired invitation',
      });
      expect(mocks.hashPassword).not.toHaveBeenCalled();
      expect(files.has('/tmp/admin-users.json')).toBe(false);
    });
  });

  
  
  

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

      
      const updated = await service.getInvitation('to-extend');
      expect(updated).not.toBeNull();
      const newExpiry = new Date(updated!.expiresAt).getTime();
      expect(newExpiry).toBeGreaterThan(originalExpiry);
      
      const diffHours = (newExpiry - originalExpiry) / (1000 * 60 * 60);
      expect(diffHours).toBeCloseTo(24, 0);
    });

    it('returns false for a used invitation', async () => {
      const invite = makeUsedInvite({ token: 'used-extend' });
      
      
      
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

      
      mocks.readFile.mockImplementation(async (path: string) => {
        if (path === '/tmp/admin-users.json') return JSON.stringify([]);
        throw new Error('not found');
      });
      await service.acceptInvitation({ token, handle: 'extenduser', password: 'pass' });

      
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

  
  
  

  describe('getStatistics', () => {
    it('returns correct counts for mixed invitation states', async () => {
      installStatefulStorage(mocks);
      const service = new InvitationService();

      
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const third = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      await service.acceptInvitation({
        token: third.invitation!.token,
        handle: 'statsuser',
        password: 'pass',
      });

      const stats = await service.getStatistics();
      
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
      
      const stats = await service.getStatistics();
      
      expect(stats.total).toBe(1);
      expect(stats.pending).toBe(1);
      expect(stats.expired).toBe(0); 
      expect(stats.used).toBe(0);
    });

    it('counts used invitations correctly', async () => {
      installStatefulStorage(mocks);
      const service = new InvitationService();
      const c1 = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const c2 = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      
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
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      await service.listPendingInvitations(); 

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
      await service.listPendingInvitations(); 

      
      expect(mocks.writeFile).not.toHaveBeenCalled();
    });
  });

  
  
  

  describe('file I/O', () => {
    it('reads invites from the configured path', async () => {
      const service = new InvitationService();
      await service.listPendingInvitations();

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/invites.json');
    });

    it('writes invitations as serialized JSON', async () => {
      const service = new InvitationService();
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      installStatefulStorage(mocks);
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'iotest',
        password: 'pass',
      });

      expect(mocks.readFile).toHaveBeenCalledWith('/tmp/admin-users.json');
    });

    it('writes admin users to the configured path during accept', async () => {
      installStatefulStorage(mocks);
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

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
      installStatefulStorage(mocks);
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'nousers',
        password: 'pass',
      });

      expect(result.success).toBe(true);
    });
  });

  
  
  

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
      await service1.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      const service2 = new InvitationService();
      
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
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to create invitation');
    });

    it('preserves invitation data through save/load cycle', async () => {
      let savedData = '';
      mocks.writeFile.mockImplementation(async (_path: string, data: string) => {
        savedData = data;
      });

      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        ...defaultCreateOptions,
        handle: 'roundtrip',
      });

      
      const parsed = JSON.parse(savedData);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].token).toBe(created.invitation!.token);
      expect(parsed[0].temporaryTotpSecret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('persists the resolved principal handle without request fallback', async () => {
      setResolvedPrincipal(mocks, {
        id: 'creator-id',
        role: 'super_admin',
        handle: 'CreatorHandle',
      });
      const service = new InvitationService();
      const result = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        role: 'admin',
      });

      expect(result.invitation).toMatchObject({
        createdBy: 'creator-id',
        createdByHandle: 'CreatorHandle',
      });
    });

    it('handles concurrent creates without data loss', async () => {
      const service = new InvitationService();

      const results = await Promise.all([
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, { ...defaultCreateOptions, handle: 'user1' }),
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, { ...defaultCreateOptions, handle: 'user2' }),
        service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, { ...defaultCreateOptions, handle: 'user3' }),
      ]);

      expect(results.every((r) => r.success)).toBe(true);

      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(3);
    });

    it('handles the case where admin users file returns invalid JSON', async () => {
      const files = installStatefulStorage(mocks);
      const service = new InvitationService();
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      files.set('/tmp/admin-users.json', 'not json');

      
      
      
      const result = await service.acceptInvitation({
        token: created.invitation!.token,
        handle: 'badjson',
        password: 'pass',
      });

      
      expect(result.success).toBe(true);
    });
  });

  
  
  

  describe('convenience functions', () => {
    it('createInvitation delegates to singleton', async () => {
      
      
      const { createInvitation } = await import('../src/service.js');
      
      const result = await createInvitation(
        DEFAULT_SERVER_AUTH_CONTEXT,
        defaultCreateOptions,
      );
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

      await expect(service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions)).rejects.toThrow(
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

  
  
  

  describe('full workflow', () => {
    it('create -> get -> accept -> verify used', async () => {
      installStatefulStorage(mocks);
      setResolvedPrincipal(mocks, {
        id: 'super-admin',
        role: 'super_admin',
        handle: 'SuperAdmin',
      });
      const service = new InvitationService();

      
      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, {
        role: 'moderator',
        handle: 'newmod',
      });
      expect(created.success).toBe(true);
      const token = created.invitation!.token;

      
      const fetched = await service.getInvitation(token);
      expect(fetched).not.toBeNull();
      expect(fetched!.role).toBe('moderator');

      const accepted = await service.acceptInvitation({
        token,
        handle: 'newmod',
        password: 'strongpass!',
      });
      expect(accepted.success).toBe(true);
      expect(accepted.user!.role).toBe('moderator');
      expect(accepted.needsOnboarding).toBe(true);

      
      const afterAccept = await service.getInvitation(token);
      expect(afterAccept).toBeNull();
    });

    it('create -> revoke -> verify gone', async () => {
      const service = new InvitationService();

      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;

      
      const before = await service.getInvitation(token);
      expect(before).not.toBeNull();

      
      const revoked = await service.revokeInvitation(token, 'admin');
      expect(revoked).toBe(true);

      
      const after = await service.getInvitation(token);
      expect(after).toBeNull();
    });

    it('create -> extend -> verify extended', async () => {
      const service = new InvitationService();

      const created = await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      const token = created.invitation!.token;
      const originalExpiry = new Date(created.invitation!.expiresAt);

      
      const extended = await service.extendInvitation(token, 48);
      expect(extended).toBe(true);

      
      const after = await service.getInvitation(token);
      expect(after).not.toBeNull();
      const newExpiry = new Date(after!.expiresAt);
      expect(newExpiry.getTime()).toBeGreaterThan(originalExpiry.getTime());
    });

    it('create multiple -> list pending -> verify count', async () => {
      const service = new InvitationService();

      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);
      await service.createInvitation(DEFAULT_SERVER_AUTH_CONTEXT, defaultCreateOptions);

      const pending = await service.listPendingInvitations();
      expect(pending).toHaveLength(3);

      const stats = await service.getStatistics();
      expect(stats.total).toBe(3);
      expect(stats.pending).toBe(3);
    });
  });
});
