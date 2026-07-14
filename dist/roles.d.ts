import type { AdminRole, InvitationPrincipal } from './types.js';
export declare const SUPPORTED_RBAC_AUTHORITY_VERSION: "tinyland-rbac/1";
declare const INVITATION_ROLE_AUTHORITY: unique symbol;
export interface InvitationRoleAuthority {
    readonly version: typeof SUPPORTED_RBAC_AUTHORITY_VERSION;
    readonly canManageRole: (actorRole: AdminRole, targetRole: AdminRole) => boolean | Promise<boolean>;
    readonly [INVITATION_ROLE_AUTHORITY]: true;
}
export interface InvitationRoleAuthoritySource {
    readonly version: string;
    readonly canManageRole: (actorRole: AdminRole, targetRole: AdminRole) => boolean | Promise<boolean>;
}
export interface InvitationRoleDecision {
    readonly principal: InvitationPrincipal;
    readonly targetRole: AdminRole;
}
/**
 * Build the immutable adapter consumed by the invitation service.
 *
 * The rank decision remains owned by the auth package (or another explicitly
 * reviewed consumer authority). This package validates only the protocol
 * version and adapter provenance; it intentionally carries no role hierarchy.
 */
export declare function createInvitationRoleAuthority(source: InvitationRoleAuthoritySource): InvitationRoleAuthority;
/** @internal Validate configuration provenance before the service is exposed. */
export declare function assertInvitationRoleAuthority(value: unknown): asserts value is InvitationRoleAuthority;
/**
 * @internal Fail closed for absent/invalid adapters. Authority exceptions
 * propagate so the service can record an operational audit event before deny.
 */
export declare function authorityAllowsInvitation(authority: InvitationRoleAuthority | undefined, decision: InvitationRoleDecision): Promise<boolean>;
export {};
//# sourceMappingURL=roles.d.ts.map