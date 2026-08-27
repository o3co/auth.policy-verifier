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

/*
 * Bounds on the remote JWKS fetch (#109). A key resolution that misses the
 * cache happens inside a verify request, so an unbounded fetch is a stall
 * vector on the decision hot path: every caller of a deployment whose provider
 * has gone dark waits for the same dead socket.
 *
 * The values match what jose applies when told nothing, so upgrading to this
 * release changes no timing. Pinning them here is the point: they are stated
 * rather than inherited (a jose release cannot silently retune the hot path),
 * and each is an operator knob — `oauth.jwt.jwksTimeoutMs`,
 * `jwksCooldownMs`, `jwksCacheMaxAgeMs`.
 */

/** Abort a JWKS fetch after this long; verification then fails as unavailable. */
export const DEFAULT_JWKS_TIMEOUT_MS = 5_000;

/**
 * Minimum spacing between JWKS fetches. A token carrying an unknown `kid`
 * triggers a refetch, and `kid` is attacker-controlled — the cooldown is what
 * keeps a stream of forged headers from turning into a fetch storm against the
 * provider. Lower it only where key rotation must be picked up faster.
 */
export const DEFAULT_JWKS_COOLDOWN_MS = 30_000;

/** How long a fetched JWKS is served from cache before it is refetched. */
export const DEFAULT_JWKS_CACHE_MAX_AGE_MS = 600_000;

/**
 * Default bind address when the config does not set one (#108).
 *
 * Loopback, not `0.0.0.0`: the verifier answers `/verify` with an authorization
 * decision, which makes a reachable port a decision oracle for anyone who can
 * route to it. The deployment this project is designed around is a sidecar —
 * the enforcement layer runs on the same host and talks to it over loopback —
 * so the default is the shape that needs no network policy to be safe.
 *
 * A containerised deployment binds all interfaces by setting `http.hostname`
 * (env `HTTP_HOSTNAME=0.0.0.0`) explicitly; that is now an opt-in.
 */
export const DEFAULT_HOSTNAME = "127.0.0.1";

/**
 * Default header carrying the caller credential when `http.callerAuth` sets a
 * token but no header name (#108).
 *
 * Deliberately not `Authorization`: that header carries the *subject* token,
 * and the two answer different questions — who the decision is about versus
 * which service is allowed to ask for one.
 */
export const DEFAULT_CALLER_AUTH_HEADER = "x-caller-token";

/**
 * Whether a deployment must authenticate the services calling `/verify` (#108).
 *
 * `false` today: caller authentication is **optional**. Making it mandatory in
 * this pass would break every container deployment and the cross-repo E2E,
 * which reach the verifier from another container with no credential wired.
 *
 * Flipping this single constant to `true` is the whole policy change: `createApp`
 * then refuses to boot without `http.callerAuth.token` instead of warning about
 * a non-loopback bind. Do it once deployments have had a release to configure a
 * credential — and note it is a BREAKING change for anyone who has not.
 */
export const CALLER_AUTH_REQUIRED = false;
