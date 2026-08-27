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

/*
 * Bounds on a presented token's own lifetime (#110). `exp` is required
 * outright — that is not a knob — but two knobs decide what a *present* set of
 * time claims is allowed to mean.
 */

/**
 * Ceiling on `now - iat`: how long after issuance a token may still be
 * presented, regardless of the `exp` its issuer chose.
 *
 * A day, and deliberately far looser than any access token should need: this is
 * a backstop against an issuer minting a decade-long `exp`, not a session
 * policy. The provider this project is paired with issues one-hour access
 * tokens, so a default under an hour would make the verifier stricter than the
 * issuer it fronts and start refusing tokens the provider still considers
 * valid — a day leaves that alone while still putting a ceiling on "forever".
 *
 * Because the bound is measured from `iat`, setting it at all makes `iat`
 * required (RFC 9068 §2.2 requires it of an access token anyway). There is no
 * "off" value: a deployment that genuinely mints long-lived tokens raises the
 * number to cover them, which is a statement of how long they live rather than
 * a switch that turns the ceiling off.
 */
export const DEFAULT_MAX_TOKEN_AGE_SECONDS = 86_400;

/**
 * Skew allowance applied to every time-claim comparison — `exp`, `nbf` and the
 * token-age ceiling alike.
 *
 * Zero by default: the verifier should not widen a token's life on its own
 * initiative, and a deployment whose clocks are disciplined (NTP, or a
 * single-host sidecar sharing the issuer's clock) needs nothing. Where the
 * issuer and the verifier keep separate clocks, `60` matches the skew the
 * paired provider allows and is the value to reach for first.
 */
export const DEFAULT_CLOCK_TOLERANCE_SECONDS = 0;

/**
 * Ceiling on the configurable clock tolerance.
 *
 * Tolerance extends the accepted life of every token the deployment sees, in
 * both directions, so an unbounded knob is a way to spell "expiry optional"
 * without ever writing it down — the failure #110 is about, re-entered through
 * the mitigation. Five minutes is more skew than a machine with working time
 * sync ever exhibits; past that the answer is to fix the clock, not to widen
 * the window.
 */
export const MAX_CLOCK_TOLERANCE_SECONDS = 300;

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
