import { describe, expect, it, vi } from 'vitest';
import {
  authorityAllowsInvitation,
  createInvitationRoleAuthority,
  SUPPORTED_RBAC_AUTHORITY_VERSION,
  type InvitationRoleAuthority,
  type InvitationRoleAuthoritySource,
} from '../src/roles.js';

const ROLES = [
  'super_admin',
  'admin',
  'moderator',
  'editor',
  'event_manager',
  'contributor',
  'member',
  'viewer',
] as const;

const RANKS = Object.freeze({
  super_admin: 100,
  admin: 90,
  moderator: 70,
  editor: 60,
  event_manager: 50,
  contributor: 40,
  member: 30,
  viewer: 10,
} as const);

function canonicalDecision(actorRole: string, targetRole: string): boolean {
  if (
    !Object.prototype.hasOwnProperty.call(RANKS, actorRole) ||
    !Object.prototype.hasOwnProperty.call(RANKS, targetRole)
  ) {
    return false;
  }

  return (
    RANKS[actorRole as keyof typeof RANKS] >
    RANKS[targetRole as keyof typeof RANKS]
  );
}

function makeAuthority(
  canManageRole: InvitationRoleAuthoritySource['canManageRole'] = canonicalDecision,
) {
  return createInvitationRoleAuthority({
    version: SUPPORTED_RBAC_AUTHORITY_VERSION,
    canManageRole,
  });
}

function principal(role: string, isActive = true) {
  return Object.freeze({
    id: 'actor',
    role,
    handle: 'actor-handle',
    isActive,
  });
}

describe('versioned invitation role authority', () => {
  it('copies and freezes a supported authority adapter', () => {
    const source: InvitationRoleAuthoritySource = {
      version: SUPPORTED_RBAC_AUTHORITY_VERSION,
      canManageRole: canonicalDecision,
    };
    const authority = createInvitationRoleAuthority(source);

    expect(authority.version).toBe('tinyland-rbac/1');
    expect(authority.canManageRole).toBe(canonicalDecision);
    expect(Object.isFrozen(authority)).toBe(true);
  });

  it('copies the callback so later source mutation cannot replace policy', async () => {
    const source = {
      version: SUPPORTED_RBAC_AUTHORITY_VERSION,
      canManageRole: vi.fn(() => true),
    };
    const original = source.canManageRole;
    const authority = createInvitationRoleAuthority(source);
    source.canManageRole = vi.fn(() => false);

    await expect(
      authorityAllowsInvitation(authority, {
        principal: principal('admin'),
        targetRole: 'viewer',
      }),
    ).resolves.toBe(true);
    expect(original).toHaveBeenCalledOnce();
    expect(source.canManageRole).not.toHaveBeenCalled();
  });

  it('rejects stale, inherited, accessor-backed, and incomplete sources', () => {
    expect(() =>
      createInvitationRoleAuthority({
        version: 'tinyland-rbac/0',
        canManageRole: canonicalDecision,
      }),
    ).toThrow('unsupported RBAC authority version');

    const inherited = Object.create({
      version: SUPPORTED_RBAC_AUTHORITY_VERSION,
      canManageRole: canonicalDecision,
    }) as InvitationRoleAuthoritySource;
    expect(() => createInvitationRoleAuthority(inherited)).toThrow(
      'unsupported RBAC authority version',
    );

    const accessorBacked = {} as InvitationRoleAuthoritySource;
    Object.defineProperties(accessorBacked, {
      version: { get: () => SUPPORTED_RBAC_AUTHORITY_VERSION },
      canManageRole: { get: () => canonicalDecision },
    });
    expect(() => createInvitationRoleAuthority(accessorBacked)).toThrow(
      'unsupported RBAC authority version',
    );

    expect(() =>
      createInvitationRoleAuthority({
        version: SUPPORTED_RBAC_AUTHORITY_VERSION,
      } as InvitationRoleAuthoritySource),
    ).toThrow('must provide canManageRole');
  });

  it('rejects forged and spread-cloned adapters even when frozen', async () => {
    const forged = Object.freeze({
      version: SUPPORTED_RBAC_AUTHORITY_VERSION,
      canManageRole: () => true,
    }) as unknown as InvitationRoleAuthority;
    const spread = Object.freeze({
      ...makeAuthority(() => true),
    }) as unknown as InvitationRoleAuthority;

    for (const authority of [forged, spread]) {
      await expect(
        authorityAllowsInvitation(authority, {
          principal: principal('viewer'),
          targetRole: 'admin',
        }),
      ).resolves.toBe(false);
    }
  });

  it('preserves a consumer authority decision for all 64 fixture role pairs', async () => {
    const authority = makeAuthority();

    for (const actorRole of ROLES) {
      for (const targetRole of ROLES) {
        await expect(
          authorityAllowsInvitation(authority, {
            principal: principal(actorRole),
            targetRole,
          }),
        ).resolves.toBe(canonicalDecision(actorRole, targetRole));
      }
    }
  });

  it('denies missing, unknown, prototype-key, and normalized aliases', async () => {
    const authority = makeAuthority();

    for (const [actorRole, targetRole] of [
      [undefined, 'viewer'],
      ['wizard', 'viewer'],
      ['constructor', 'viewer'],
      ['SUPER_ADMIN', 'viewer'],
      ['super-admin', 'viewer'],
      ['admin', '__proto__'],
    ] as const) {
      await expect(
        authorityAllowsInvitation(authority, {
          principal: principal(actorRole as string),
          targetRole,
        }),
      ).resolves.toBe(false);
    }
  });

  it('surfaces authority failures for service-level audit and denies non-boolean results', async () => {
    const throwing = makeAuthority(async () => {
      throw new Error('authority unavailable');
    });
    const truthy = makeAuthority(
      (() => 'yes') as unknown as InvitationRoleAuthoritySource['canManageRole'],
    );
    const decision = {
      principal: principal('super_admin'),
      targetRole: 'viewer',
    };

    await expect(authorityAllowsInvitation(throwing, decision)).rejects.toThrow(
      'authority unavailable',
    );
    await expect(authorityAllowsInvitation(truthy, decision)).resolves.toBe(false);
  });

  it('denies an inactive resolved principal before consulting authority', async () => {
    const canManageRole = vi.fn(() => true);
    const authority = makeAuthority(canManageRole);

    await expect(
      authorityAllowsInvitation(authority, {
        principal: principal('super_admin', false),
        targetRole: 'viewer',
      }),
    ).resolves.toBe(false);
    expect(canManageRole).not.toHaveBeenCalled();
  });
});
