import type { AdminRole } from './types.js';
/**
 * Built-in role authority, highest → lowest. Mirrors the canonical
 * `canManageRole()` ordering in `@tummycrypt/tinyland-auth`
 * (src/core/permissions/index.ts) so the standalone default gate matches the
 * policy the app and vendored copies already enforce.
 *
 * `AdminRole` is deliberately widened to `string` (consumer-defined vocabularies),
 * so any role NOT present here is treated as unknown and denied — fail closed.
 */
export declare const ROLE_HIERARCHY: readonly ["super_admin", "admin", "editor", "event_manager", "moderator", "contributor", "member", "viewer"];
/**
 * Real role-hierarchy authority gate (TIN-1607 R3).
 *
 * A creator may mint an invitation for `targetRole` ONLY when the creator
 * STRICTLY outranks the target. Missing `createdByRole`, or any role outside
 * {@link ROLE_HIERARCHY}, denies the request. This is the DEFAULT policy used
 * whenever a consumer does not inject `config.canCreateInviteForRole`, so the
 * package never mints unrestricted invitations when left unwired.
 *
 * Semantics match `tinyland-auth` `canManageRole()`:
 *   - normalize (lowercase, `-` → `_`)
 *   - unknown actor or target → `false`
 *   - allowed iff `actorIndex < targetIndex` (strictly higher authority)
 */
export declare function defaultCanCreateInviteForRole(args: {
    createdBy: string;
    createdByRole?: AdminRole;
    targetRole: AdminRole;
}): boolean;
//# sourceMappingURL=roles.d.ts.map