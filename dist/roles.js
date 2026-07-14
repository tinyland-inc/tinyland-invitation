export const SUPPORTED_RBAC_AUTHORITY_VERSION = 'tinyland-rbac/1';
const INVITATION_ROLE_AUTHORITY = Symbol('tinyland-invitation-role-authority');
const INVITATION_ROLE_AUTHORITIES = new WeakSet();
function ownDataProperty(value, key) {
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
export function createInvitationRoleAuthority(source) {
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
    };
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
function isInvitationRoleAuthority(value) {
    return (typeof value === 'object' &&
        value !== null &&
        INVITATION_ROLE_AUTHORITIES.has(value) &&
        Object.isFrozen(value) &&
        ownDataProperty(value, 'version') === SUPPORTED_RBAC_AUTHORITY_VERSION &&
        typeof ownDataProperty(value, 'canManageRole') === 'function');
}
/** @internal Validate configuration provenance before the service is exposed. */
export function assertInvitationRoleAuthority(value) {
    if (!isInvitationRoleAuthority(value)) {
        throw new Error('roleAuthority must be created by this package instance with createInvitationRoleAuthority()');
    }
}
/**
 * @internal Fail closed for absent/invalid adapters. Authority exceptions
 * propagate so the service can record an operational audit event before deny.
 */
export async function authorityAllowsInvitation(authority, decision) {
    if (!decision.principal.isActive || !isInvitationRoleAuthority(authority)) {
        return false;
    }
    const canManageRole = authority.canManageRole;
    return ((await canManageRole(decision.principal.role, decision.targetRole)) === true);
}
