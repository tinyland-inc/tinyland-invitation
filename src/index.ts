/**
 * @tinyland-inc/tinyland-invitation
 *
 * Admin invitation management with TOTP setup and audit logging.
 * All external dependencies are injected via configure().
 */

export { configure, getConfig, resetConfig } from './config.js';
export type { InvitationConfig } from './config.js';

export {
  InvitationService,
  invitationService,
  createInvitation,
  acceptInvitation,
  getInvitation,
} from './service.js';

export type {
  AdminRole,
  AdminInvite,
  AdminUser,
  InvitationCreateOptions,
  InvitationAcceptData,
  InvitationResult,
  AcceptResult,
  InvitationStatistics,
} from './types.js';
