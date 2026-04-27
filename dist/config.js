let currentConfig = null;
export function configure(config) {
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
