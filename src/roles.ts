import type { AdminRole } from './types.js';

export const SUPPORTED_RBAC_AUTHORITY_VERSION = 'tinyland-rbac/1' as const;

const INVITATION_ROLE_AUTHORITY = Symbol('tinyland-invitation-role-authority');
const INVITATION_ROLE_AUTHORITIES = new WeakSet<object>();

export interface InvitationRoleAuthority {
  readonly version: typeof SUPPORTED_RBAC_AUTHORITY_VERSION;
  readonly canManageRole: (
    actorRole: AdminRole,
    targetRole: AdminRole,
  ) => boolean | Promise<boolean>;
  readonly [INVITATION_ROLE_AUTHORITY]: true;
}

export interface InvitationRoleAuthoritySource {
  readonly version: string;
  readonly canManageRole: (
    actorRole: AdminRole,
    targetRole: AdminRole,
  ) => boolean | Promise<boolean>;
}

export interface InvitationRoleDecision {
  readonly createdBy: string;
  readonly createdByRole?: AdminRole;
  readonly targetRole: AdminRole;
}

function ownDataProperty(value: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}

/**
 * Build the immutable adapter consumed by the invitation service.
 *
 * The rank decision remains owned by the auth package (or another explicitly
 * reviewed consumer authority). This package validates only the protocol
 * version and adapter provenance; it intentionally carries no role hierarchy.
 */
export function createInvitationRoleAuthority(
  source: InvitationRoleAuthoritySource,
): InvitationRoleAuthority {
  if (typeof source !== 'object' || source === null) {
    throw new Error('invitation role authority source is required');
  }

  const version = ownDataProperty(source, 'version');
  if (version !== SUPPORTED_RBAC_AUTHORITY_VERSION) {
    throw new Error(`unsupported RBAC authority version: ${String(version)}`);
  }

  const canManageRole = ownDataProperty(source, 'canManageRole');
  if (typeof canManageRole !== 'function') {
    throw new Error('invitation role authority must provide canManageRole');
  }

  const authority = {
    version: SUPPORTED_RBAC_AUTHORITY_VERSION,
    canManageRole,
  } as unknown as InvitationRoleAuthority;

  Object.defineProperty(authority, INVITATION_ROLE_AUTHORITY, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  Object.freeze(authority);
  INVITATION_ROLE_AUTHORITIES.add(authority);
  return authority;
}

function isInvitationRoleAuthority(value: unknown): value is InvitationRoleAuthority {
  return (
    typeof value === 'object' &&
    value !== null &&
    INVITATION_ROLE_AUTHORITIES.has(value) &&
    Object.isFrozen(value) &&
    ownDataProperty(value, 'version') === SUPPORTED_RBAC_AUTHORITY_VERSION &&
    typeof ownDataProperty(value, 'canManageRole') === 'function'
  );
}

/** @internal Validate configuration provenance before the service is exposed. */
export function assertInvitationRoleAuthority(
  value: unknown,
): asserts value is InvitationRoleAuthority {
  if (!isInvitationRoleAuthority(value)) {
    throw new Error(
      'roleAuthority must be created by this package instance with createInvitationRoleAuthority()',
    );
  }
}

/**
 * @internal Fail closed for absent/invalid adapters. Authority exceptions
 * propagate so the service can record an operational audit event before deny.
 */
export async function authorityAllowsInvitation(
  authority: InvitationRoleAuthority | undefined,
  decision: InvitationRoleDecision,
): Promise<boolean> {
  if (!decision.createdByRole || !isInvitationRoleAuthority(authority)) {
    return false;
  }

  const canManageRole = authority.canManageRole;
  return (
    (await canManageRole(decision.createdByRole, decision.targetRole)) === true
  );
}
