/**
 * Dependency-light defaults shared by the config schema and the routers.
 *
 * Lives apart from both so that config-only consumers of `AppConfigSchema`
 * do not pull in the router implementation (and its transitive express/jose
 * imports), and the routers do not depend on the zod schema.
 */

/**
 * Default cap on `POST /verify/batch` entries when the config does not set one.
 * Single definition — `AppConfigSchema`'s `verify.maxBatchSize` default and
 * the verify router's fallback both import it.
 */
export const DEFAULT_MAX_BATCH_SIZE = 50;
