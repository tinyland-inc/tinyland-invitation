/**
 * Typed errors for the invitation authority surface.
 *
 * `createInvitation()` throws `InvitationError` with code `'forbidden'` when the
 * role-authority gate denies a request (TIN-1607 R3). Throwing — rather than
 * returning a soft `{ success: false }` — guarantees a mis-wired consumer fails
 * CLOSED: a caller that neglects to inspect the result can never silently treat a
 * denied request as a minted invitation.
 */
export type InvitationErrorCode = 'forbidden';
export declare class InvitationError extends Error {
    readonly code: InvitationErrorCode;
    constructor(message: string, code?: InvitationErrorCode);
}
//# sourceMappingURL=errors.d.ts.map