// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * Dependency-light defaults shared by the config schema and the routers, kept
 * apart from both so that config-only consumers of `AppConfigSchema` do not
 * pull in the router implementation (and its express/jose imports), and the
 * routers do not depend on the zod schema.
 */

/**
 * Default cap on `POST /verify/batch` entries. `AppConfigSchema`'s
 * `verify.maxBatchSize` default and the verify router's fallback both import it.
 */
export const DEFAULT_MAX_BATCH_SIZE = 50;

/**
 * How many of a batch's entries are decided at once.
 *
 * The collector concurrency cap is per pipeline, **per decision**, and does not
 * bound the batch: without this, one request at `DEFAULT_MAX_BATCH_SIZE` could
 * hold `50 × DEFAULT_COLLECTOR_CONCURRENCY` collectors in flight per pipeline,
 * from a single HTTP request, past any per-request rate limit in front of
 * `/verify`.
 *
 * Eight, as for `DEFAULT_COLLECTOR_CONCURRENCY`: a small batch still decides in
 * one wave, and the per-request ceiling is 8 × 8 per pipeline, not 50 × 8.
 */
export const DEFAULT_BATCH_CONCURRENCY = 8;

/*
 * Bounds on what one `/verify` request may carry. Every one of them is an input
 * a caller chooses, so each has a stated size; they are numeric knobs like every
 * other, read through `resolveBound` at both boundaries. The values are generous
 * for a real caller and small for a prober: `resource` and `action` are
 * structural identifiers, not free text, and `context` is a handful of declared
 * fields a collector was configured to promote.
 */

/**
 * Ceiling on the JSON body `POST /verify` and `POST /verify/batch` will read,
 * in bytes: the `limit` handed to `express.json()`, which refuses a body over it
 * before any of it is held in memory as objects.
 *
 * This is the outer envelope, and the bound that binds first on a large batch:
 * the per-field limits below say what *one* entry may carry, not what N of them
 * add up to. A deployment sending wide contexts across a full 50-entry batch
 * raises this knob.
 */
export const DEFAULT_MAX_BODY_BYTES = 65_536;

/**
 * Ceiling on the `resource` string, in characters. Generous for the identifiers
 * the shipped grammar describes (`org:123.project:abc.document:42` is 31
 * characters) and for a percent-encoded id, while bounding what is handed to
 * the configured `ResourceParser`, which the router runs before the token is
 * verified.
 */
export const DEFAULT_MAX_RESOURCE_LENGTH = 512;

/**
 * Ceiling on the `action` string, in characters.
 *
 * Shorter than `resource` because an action is a verb, not a path: `read`,
 * `write`, `admin:manage`. It is also concatenated into the
 * `{action}:{resourceType}` scope `ResourceActionScopeRuleCollector` requires,
 * so a long one names a scope no issuer could grant.
 */
export const DEFAULT_MAX_ACTION_LENGTH = 64;

/**
 * Ceiling on the size of the request `context`, counted as every property and
 * every array element in the whole tree, at every depth. Counted over the tree
 * rather than the top-level keys because nesting is a supported shape
 * (`RequestContextAttributeCollector` reads dot paths such as `tenant.id`).
 *
 * It also bounds the *depth*: each level of nesting costs at least one entry, so
 * no separate depth knob is needed to keep the validating walk finite.
 */
export const DEFAULT_MAX_CONTEXT_ENTRIES = 64;

/**
 * Ceiling on every string inside `context`, in characters — property names and
 * string values alike.
 *
 * A collector reads declared fields out of `requestContext` and promotes them
 * into attributes that rules compare; a kilobyte is far more than any such
 * field is, and a value larger than that is a payload rather than an attribute.
 */
export const DEFAULT_MAX_CONTEXT_VALUE_LENGTH = 1_024;

/*
 * Bounds on the collector fan-out, re-exported from core rather than restated.
 * The numbers belong to the engine: `AttributePipeline` and `RulePipeline`
 * enforce them, and a library consumer who never loads this package still gets
 * them. A second copy here could drift, and the config file's default and the
 * pipeline's would disagree about what an unset knob means.
 *
 * This is the one import this module has. Core carries no dependencies of its
 * own, so a config-only consumer of `AppConfigSchema` still pulls in nothing but
 * the engine's own vocabulary — the property `config/bounds.mts` guards, and the
 * reason nothing heavier may be reached for from here.
 *
 * `MAX_TIMER_MS` is a fact about `setTimeout`, defined once beside the engine's
 * own timer use, and the ceiling the JWKS fetch timeout and the collector and
 * rule budgets are held to; `jwksCooldownMs` and `jwksCacheMaxAgeMs` have no
 * ceiling.
 */
export {
	DEFAULT_COLLECT_DEADLINE_MS,
	DEFAULT_COLLECTOR_CONCURRENCY,
	DEFAULT_COLLECTOR_TIMEOUT_MS,
	DEFAULT_EVALUATE_DEADLINE_MS,
	DEFAULT_RULE_TIMEOUT_MS,
	MAX_TIMER_MS,
} from "@o3co/auth.policy-verifier.core";

/*
 * Bounds on the remote JWKS fetch. A key resolution that misses the cache
 * happens inside a verify request, so an unbounded fetch is a stall vector on
 * the decision hot path: every caller of a deployment whose provider has gone
 * dark waits for the same dead socket.
 *
 * The values match what jose applies when told nothing, but are stated rather
 * than inherited, so a jose release cannot silently retune the hot path. Each is
 * an operator knob: `oauth.jwt.jwksTimeoutMs`, `jwksCooldownMs`,
 * `jwksCacheMaxAgeMs`.
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
 * Bounds on a presented token's own lifetime. `exp` is required outright, not
 * a knob; two knobs decide what a *present* set of time claims may mean.
 */

/**
 * Ceiling on `now - iat`: how long after issuance a token may still be
 * presented, regardless of the `exp` its issuer chose.
 *
 * A day: a backstop against an issuer minting a decade-long `exp`, not a
 * session policy. The paired provider issues one-hour access tokens, and a
 * default under an hour would refuse tokens it still considers valid.
 *
 * Because the bound is measured from `iat`, `iat` is required (RFC 9068 §2.2
 * requires it of an access token anyway). There is no "off" value: a deployment
 * that mints long-lived tokens raises the number to cover them.
 */
export const DEFAULT_MAX_TOKEN_AGE_SECONDS = 86_400;

/**
 * Skew allowance applied to every time-claim comparison: `exp`, `nbf` and the
 * token-age ceiling alike.
 *
 * Zero by default: the verifier should not widen a token's life on its own
 * initiative, and disciplined clocks (NTP, or a single-host sidecar sharing the
 * issuer's clock) need nothing. Where the issuer and the verifier keep separate
 * clocks, `60` matches the skew the paired provider allows.
 */
export const DEFAULT_CLOCK_TOLERANCE_SECONDS = 0;

/**
 * Ceiling on the configurable clock tolerance. Tolerance extends the accepted
 * life of every token, in both directions, so an unbounded knob would spell
 * "expiry optional" without ever writing it down. Five minutes is more skew than
 * a machine with working time sync exhibits; past that, fix the clock.
 */
export const MAX_CLOCK_TOLERANCE_SECONDS = 300;

/**
 * Floor on the key material an HS256 secret must carry, in bytes.
 *
 * 32 bytes = 256 bits = the output width of SHA-256, which is the most an HS256
 * key can contribute. RFC 7518 §3.2: "A key of the same size as the hash output
 * ... or larger MUST be used." With a symmetric algorithm, guessing the secret
 * is not read access to tokens, it is the ability to MINT them for any subject.
 *
 * The same number auth.provider enforces, deliberately: the two services share
 * one secret, so a floor that either side applies alone is a floor neither side
 * has. This is the one statement of that reasoning; `config/secretEntropy.mts`
 * and `config/hs256Rotation.mts` point here.
 *
 * It is measured on DECODED material at the smallest plausible reading (see
 * `config/secretEntropy.mts`), so `openssl rand -hex 16` (32 characters, 16
 * bytes) fails rather than passing on its character count.
 */
export const MIN_SECRET_ENTROPY_BYTES = 32;

/**
 * Ceiling on `oauth.jwt.previousSecrets`: how many retired HS256 secrets a
 * deployment may hold alongside the current one.
 *
 * It is the per-verification work budget. An HS256 token may arrive with no
 * `kid` header, and the only way to verify one is to try the secrets in turn,
 * so the length of this list is the number of HMAC computations an
 * unauthenticated caller can force on the decision hot path per request.
 *
 * Three: one overlap slot for a rotation, one for a second rotation started
 * before the first window closed, and a spare. A deployment that needs more
 * should let the windows close (`expiresAt`) rather than keep old keys live,
 * since every entry here can still MINT tokens for anyone who holds it.
 */
export const MAX_PREVIOUS_SECRETS = 3;

/**
 * Default bind address when the config does not set one.
 *
 * Loopback, not `0.0.0.0`: `/verify` answers with an authorization decision, so
 * a reachable port is a decision oracle for anyone who can route to it. The
 * deployment this project is designed around is a sidecar reached over
 * loopback, which needs no network policy to be safe. A containerised
 * deployment binds all interfaces by setting `http.hostname` (env
 * `HTTP_HOSTNAME=0.0.0.0`) explicitly.
 */
export const DEFAULT_HOSTNAME = "127.0.0.1";

/** Port the server listens on when the config does not set one. */
export const DEFAULT_HTTP_PORT = 3000;

/**
 * Largest bindable TCP port, the 16-bit ceiling, and the only thing `http.port`
 * is held to beyond being a positive integer.
 *
 * The floor is 1 rather than 0 although `listen(0)` is legal: it asks the OS for
 * an arbitrary free port, so the address the enforcement layer was configured to
 * call stops resolving to this process.
 */
export const MAX_TCP_PORT = 65_535;

/**
 * Default header carrying the caller credential when `http.callerAuth` sets a
 * token but no header name.
 *
 * Deliberately not `Authorization`: that header carries the *subject* token,
 * and the two answer different questions — who the decision is about versus
 * which service is allowed to ask for one.
 */
export const DEFAULT_CALLER_AUTH_HEADER = "x-caller-token";

/**
 * Whether a deployment must authenticate the services calling `/verify`.
 *
 * `false`: caller authentication is **optional**, because container
 * deployments and the cross-repo E2E reach the verifier from another container
 * with no credential wired. Set to `true`, `createApp` refuses to boot without
 * `http.callerAuth.token` instead of warning about a non-loopback bind — a
 * BREAKING change for any deployment that has not configured a credential.
 */
export const CALLER_AUTH_REQUIRED = false;
