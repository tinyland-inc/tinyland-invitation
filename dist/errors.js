export class InvitationError extends Error {
    code;
    constructor(message, code = 'forbidden') {
        super(message);
        this.name = 'InvitationError';
        this.code = code;
        // Preserve prototype chain across the TS/ES class-extends-Error boundary so
        // `err instanceof InvitationError` holds for downcompiled targets.
        Object.setPrototypeOf(this, InvitationError.prototype);
    }
}
