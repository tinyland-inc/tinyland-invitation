import { assertInvitationRoleAuthority } from './roles.js';
let currentConfig = null;
export function configure(config) {
    assertInvitationRoleAuthority(config.roleAuthority);
    if (typeof config.resolveCreatorRole !== 'function') {
        throw new Error('resolveCreatorRole must be a trusted server-side function');
    }
    currentConfig = config;
}
export function getConfig() {
    if (!currentConfig) {
        throw new Error('tinyland-invitation is not configured. Call configure() before using the service.');
    }
    return currentConfig;
}
export function resetConfig() {
    currentConfig = null;
}
