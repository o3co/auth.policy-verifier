// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The zod schema for the HOCON application config (`AppConfigSchema`) and the
 * type inferred from it. It is the first of the two config boundaries:
 * `createApp` re-checks what a hand-built config, which never passed through
 * this schema, could get wrong.
 */

import { z } from "zod";
import { checkAudienceClaim, DEFAULT_AUDIENCE_CLAIM } from "./audienceClaim.mjs";
import { type BoundSpec, NUMERIC_BOUNDS, resolveBound } from "./bounds.mjs";
import {
	DEFAULT_BATCH_CONCURRENCY,
	DEFAULT_CALLER_AUTH_HEADER,
	DEFAULT_COLLECT_DEADLINE_MS,
	DEFAULT_COLLECTOR_CONCURRENCY,
	DEFAULT_COLLECTOR_TIMEOUT_MS,
	DEFAULT_EVALUATE_DEADLINE_MS,
	DEFAULT_HOSTNAME,
	DEFAULT_HTTP_PORT,
	DEFAULT_MAX_ACTION_LENGTH,
	DEFAULT_MAX_BATCH_SIZE,
	DEFAULT_MAX_BODY_BYTES,
	DEFAULT_MAX_CONTEXT_ENTRIES,
	DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
	DEFAULT_MAX_RESOURCE_LENGTH,
	DEFAULT_RULE_TIMEOUT_MS,
} from "./defaults.mjs";
import {
	checkEvaluationInResponse,
	DEFAULT_EVALUATION_IN_RESPONSE,
} from "./evaluationInResponse.mjs";
import { checkHs256Rotation } from "./hs256Rotation.mjs";
import { checkJwksUri } from "./jwks.mjs";
import {
	checkTokenAuthenticatorSelection,
	JWT_TOKEN_AUTHENTICATOR,
} from "./tokenAuthenticatorSelection.mjs";

/**
 * Migration message for the removed `oauth.jwt` wire keys
 * ({@link JWT_MODE_REMOVED_KEYS}). Emitted by the schema for parsed configs and
 * by `createApp` for hand-built ones, so an operator
 * upgrading across the break always gets the same actionable pointer instead
 * of a puzzling "issuer is required" from a silently-defaulted mode.
 */
export const JWT_MODE_MIGRATION_MESSAGE =
	'oauth.jwt.validate/allowInsecureDecode were replaced by oauth.jwt.mode; set mode = "verify" or the explicit "insecure-decode"';

/**
 * The removed `oauth.jwt` keys, refused by both boundaries with
 * {@link JWT_MODE_MIGRATION_MESSAGE}.
 *
 * Shared for the same reason the message is: the schema refuses these for
 * parsed configs and `createApp` for hand-built ones, and a key on one list
 * only would be refused on one path and silently accepted on the other —
 * reinterpreted as a defaulted verify mode.
 *
 * Not re-exported from the package index: this is how the two boundaries agree
 * with each other, whereas the message is what an operator reads.
 */
export const JWT_MODE_REMOVED_KEYS = ["validate", "allowInsecureDecode"] as const;

/**
 * One numeric knob, read at this boundary by the function that reads it at the
 * other one.
 *
 * `resolveBound` decides everything about the knob: the default when the key is
 * absent, the coercion of the string a HOCON env substitution delivers, the
 * range, and the wording of the refusal. This wrapper only carries the verdict
 * into zod's issue list at the path the operator wrote — see AGENTS.md,
 * "Two-Boundary Config Validation".
 *
 * `z.unknown().optional()` and not `z.coerce.number()`: the check must see the
 * value exactly as the operator wrote it, so that zod neither refuses it in
 * its own words nor coerces it first.
 *
 * The issue is non-fatal (`z.NEVER` marks the value unusable without aborting
 * the parse), so two bad knobs in one block are both reported. zod still skips
 * a block's `superRefine` once any field in that block has failed, so a
 * refused knob and a missing `issuer` in the same `oauth.jwt` are two round
 * trips; a refused knob in a *different* block (`http.port`) leaves
 * `oauth.jwt`'s `superRefine` running.
 *
 * @param path Config path of the block this knob sits in, as the operator wrote
 * it — `"oauth.jwt"`, `"http"`, `"verify"`. It is what makes the message here
 * identical to the runtime guard's.
 */
function boundedNumber(spec: BoundSpec, path: string) {
	return z
		.unknown()
		.optional()
		.transform((value, ctx) => {
			try {
				return resolveBound(value, spec, path);
			} catch (cause) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: cause instanceof Error ? cause.message : String(cause),
				});
				return z.NEVER;
			}
		});
}

const collectorSchema = z
	.object({
		collector: z.string(),
	})
	.passthrough();

/**
 * The built-in JWT authenticator's block, `oauth.jwt`. Parsed when
 * `oauth.authenticator` selects `"jwt"` — see the `oauth` transform below.
 * Under another authenticator the block is refused rather than carried, so
 * that authenticator's keys live under its own sub-block.
 */
const OAuthJwtSchema = z
	.object({
		// Free-form, so a user-registered algorithm can be selected from config
		// without editing the schema. The built-in ones (HS256 / RS256 / ES256 /
		// EdDSA) have their key material checked in `superRefine` below; a custom
		// one validates its own config in its `KeyResolverFactory`.
		algorithm: z.string().default("HS256"),
		/**
		 * The HS256 shared secret. Required whenever the algorithm is
		 * HS256 and the mode is `"verify"`, and held to the entropy floor
		 * in `superRefine` below: the same value verifies and
		 * signs, so a guessable one is not a read of tokens but the
		 * ability to mint them. `.optional()` here because the asymmetric
		 * algorithms have no use for it.
		 */
		secret: z.string().optional(),
		/**
		 * Names the HS256 secret the issuer currently signs with, the same
		 * `kid` auth.provider stamps into every token it mints.
		 *
		 * Optional: with no `kid` configured the token header is never
		 * consulted and the single `secret` verifies everything.
		 * Setting it starts pinning the header, and `previousSecrets`
		 * requires it — nothing else tells the current secret apart from
		 * the retired ones.
		 *
		 * HS256 only. The asymmetric algorithms match `kid` against the
		 * JWKS they fetch, which is jose's job and not a config key.
		 */
		kid: z.string().optional(),
		/**
		 * HS256 secrets a rotation retired but has not finished retiring,
		 * each with the moment its overlap window closes. Without them the
		 * verifier holds one secret, and every token still in flight is
		 * refused the instant the provider signs with a new one. The shape
		 * is auth.provider's `previousSecrets` verbatim, so an operator
		 * moves the same pair of values on both sides.
		 *
		 * Capped at `MAX_PREVIOUS_SECRETS` and checked again in
		 * `config/hs256Rotation.mts`: a token carrying no `kid` is tried
		 * against every configured secret, so the list length is the work
		 * one unauthenticated request can force. Each entry's `secret`
		 * clears the same entropy floor the current one does — a retired
		 * secret verifies for its whole overlap window, so it can mint
		 * tokens exactly as the current one can.
		 *
		 * `.optional()` and not `.nullish()`: the only ways to say
		 * "nothing is being rotated" are omitting the key and `[]`. A
		 * `null` in a config was produced rather than written (an
		 * unrendered template, a missing env var), so it is refused, here
		 * and identically in `checkHs256Rotation` for hand-built configs.
		 */
		previousSecrets: z
			.array(
				z.object({
					kid: z.string(),
					secret: z.string(),
					expiresAt: z.string(),
				}),
			)
			.optional(),
		/**
		 * JWKS endpoint for the asymmetric algorithms. Must be https — or
		 * http on a loopback host, the development carve-out documented in
		 * `config/jwks.mts`. The scheme is checked in `superRefine`
		 * below so a plaintext endpoint fails at config-parse time, at boot,
		 * rather than at the first request that misses the key cache.
		 */
		jwksUri: z.string().optional(),
		// Bounds on the JWKS fetch, which happens inside a verify request
		// whenever key resolution misses the cache. Read through
		// `resolveBound`, so this boundary and `resolveJwksFetchBounds` cannot
		// disagree about what a value means. What each admits is stated once,
		// in `config/bounds.mts`.
		jwksTimeoutMs: boundedNumber(NUMERIC_BOUNDS.jwksTimeoutMs, "oauth.jwt"),
		jwksCooldownMs: boundedNumber(NUMERIC_BOUNDS.jwksCooldownMs, "oauth.jwt"),
		jwksCacheMaxAgeMs: boundedNumber(NUMERIC_BOUNDS.jwksCacheMaxAgeMs, "oauth.jwt"),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		/**
		 * How the verifier treats bearer tokens. `"verify"` (the default)
		 * fully verifies signature, iss, aud and typ; `"insecure-decode"` is the
		 * test-only mode that decodes without signature verification (`exp` /
		 * `nbf` are still enforced at request time). The value itself is the
		 * consent: an accidental env-var flip can produce a stray boolean, but
		 * never the literal string `"insecure-decode"`, so one mistyped variable
		 * cannot disable all token verification. The removed pair `validate` /
		 * `allowInsecureDecode` is rejected below with a migration message.
		 */
		mode: z.enum(["verify", "insecure-decode"]).default("verify"),
		// RFC 9068 §4 — a resource server validates iss and aud, not just the
		// signature. Both are required whenever mode is "verify" (see superRefine).
		issuer: z.union([z.string(), z.array(z.string())]).optional(),
		audience: z.union([z.string(), z.array(z.string())]).optional(),
		// Accepted `typ` header. `at+jwt` is the RFC 9068 access-token type; pinning
		// it rejects id_tokens, refresh tokens and logout tokens signed with the same key.
		// The literal `"*"` pins nothing — any `typ`, or none — for issuers whose
		// tokens carry no `typ` header (`UNPINNED_TOKEN_TYPE`).
		tokenType: z.string().default("at+jwt"),
		/**
		 * The claim the audience is read from. `aud` (the default) is jose's
		 * own check; `azp` binds a Clerk session token, `client_id` a Cognito
		 * access token — the claim compared changes, `audience` stays required.
		 * Read as `unknown` so the one shared function decides what a
		 * well-formed name is at both boundaries; the `transform` below
		 * writes the resolved name back.
		 */
		audienceClaim: z.unknown().optional(),
		/**
		 * Bounds on a presented token's own lifetime. Both apply in every
		 * mode: `insecure-decode` restates them by hand, so the two modes
		 * cannot disagree about the same token. Read through `resolveBound`,
		 * so this boundary and `resolveJwtTimeClaimBounds` cannot disagree
		 * about what a value means.
		 *
		 * `maxTokenAgeSeconds` is the ceiling on `now - iat` — what refuses a
		 * token whose issuer set `exp` years out — and setting it makes `iat`
		 * required (RFC 9068 §2.2 requires it anyway). `exp` itself is
		 * required unconditionally and has no knob: a knob to accept tokens
		 * that never expire is the bug, not the setting.
		 */
		maxTokenAgeSeconds: boundedNumber(NUMERIC_BOUNDS.maxTokenAgeSeconds, "oauth.jwt"),
		/**
		 * Skew allowance on every time-claim comparison. Bounded above
		 * because tolerance lengthens the accepted life of every token the
		 * deployment sees — an unbounded knob is a way to spell "expiry
		 * optional" without writing it down. `60` matches the skew the paired
		 * provider allows and is the value to reach for when the issuer and
		 * the verifier keep separate clocks.
		 */
		clockToleranceSeconds: boundedNumber(NUMERIC_BOUNDS.clockToleranceSeconds, "oauth.jwt"),
	})
	.passthrough()
	.superRefine((data, ctx) => {
		// Hard-error on the removed wire keys. `.passthrough()` would otherwise
		// let them ride along silently — and a decode-only config in the
		// removed spelling (`validate=false` + `allowInsecureDecode=true`) would
		// be reinterpreted as the defaulted verify mode, failing with an
		// unrelated "issuer is required" instead of migration guidance.
		let hasStaleKey = false;
		for (const staleKey of JWT_MODE_REMOVED_KEYS) {
			if (staleKey in data) {
				hasStaleKey = true;
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: JWT_MODE_MIGRATION_MESSAGE,
					path: [staleKey],
				});
			}
		}
		if (hasStaleKey) {
			return; // the operator's intended mode is unknowable; stop here
		}
		// A config-shape check, so it applies in every mode — the guard
		// reads it in both branches too.
		const audienceClaim = checkAudienceClaim(data.audienceClaim);
		if (!audienceClaim.ok) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: audienceClaim.message,
				path: ["audienceClaim"],
			});
		}
		if (data.mode === "insecure-decode") {
			// Decode-only mode: no signature check (exp/nbf are still enforced
			// at request time, but nothing else is). The mode string itself is
			// the explicit consent — see the `mode` doc comment.
			return; // key-material checks below only apply when verifying
		}
		const issuers = Array.isArray(data.issuer) ? data.issuer : [data.issuer];
		const audiences = Array.isArray(data.audience) ? data.audience : [data.audience];
		if (issuers.length === 0 || issuers.some((i) => !i)) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: 'issuer is required when mode is "verify" (RFC 9068 §4)',
				path: ["issuer"],
			});
		}
		if (audiences.length === 0 || audiences.some((a) => !a)) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: 'audience is required when mode is "verify" (RFC 9068 §4)',
				path: ["audience"],
			});
		}
		if (!data.tokenType) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: 'tokenType must not be empty when mode is "verify" (RFC 9068 §4)',
				path: ["tokenType"],
			});
		}
		if (data.algorithm === "HS256" && !data.secret) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "secret is required for HS256",
			});
		}
		if (data.algorithm === "HS256") {
			// The HS256 secret contract — the rotation shape,
			// and the entropy floor over `secret` and every
			// `previousSecrets[].secret` — is stated once, in
			// `config/hs256Rotation.mts`, and spent twice: here for config
			// files, and in the HS256 KeyResolverFactory for hand-built
			// configs that never met this schema. Every issue is reported
			// at the path the operator wrote, so a rotation block with two
			// mistakes takes one round trip to fix.
			const rotation = checkHs256Rotation(data);
			if (!rotation.ok) {
				for (const issue of rotation.issues) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: issue.message,
						path: issue.path,
					});
				}
			}
		}
		const isBuiltinAsymmetric = ["RS256", "ES256", "EdDSA"].includes(data.algorithm);
		if (isBuiltinAsymmetric && !data.jwksUri && !data.publicKey && !data.publicKeyPath) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `jwksUri or publicKey/publicKeyPath is required for ${data.algorithm}`,
			});
		}
		if (isBuiltinAsymmetric && data.previousSecrets !== undefined) {
			// Mirrors auth.provider's guard in the other direction. The
			// asymmetric algorithms rotate through the JWKS the provider
			// publishes, so a `previousSecrets` block carried over from an
			// HS256 config configures nothing — and being silently dropped
			// is how an operator ends up believing a rotation is covered
			// when it is not.
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					`previousSecrets is not valid for ${data.algorithm} — it is the HS256 ` +
					"rotation field. Asymmetric keys rotate through the JWKS at jwksUri, which " +
					"carries every key the issuer currently publishes.",
				path: ["previousSecrets"],
			});
		}
		// Transport security for the key source: a plaintext JWKS
		// endpoint lets anyone on the path substitute signing keys, so it
		// must not survive to the first request. Checked inside the verify
		// branch, like the key material above — in decode-only mode no key
		// is ever fetched, and failing to boot over an unused URI would
		// only puzzle the operator.
		if (data.jwksUri !== undefined) {
			const jwks = checkJwksUri(data.jwksUri);
			if (!jwks.ok) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: jwks.message,
					path: ["jwksUri"],
				});
			}
		}
	})
	.transform((data) => {
		// Write the resolved claim back, so the parsed config carries
		// the default the operator relied on. The refinement above already
		// refused a malformed value; the fallback only keeps the type honest.
		const audienceClaim = checkAudienceClaim(data.audienceClaim);
		return {
			...data,
			audienceClaim: audienceClaim.ok ? audienceClaim.claim : DEFAULT_AUDIENCE_CLAIM,
		};
	});

/**
 * The parsed `oauth` block. `jwt` is present exactly when `"jwt"` is
 * selected, and then it is the built-in block's parsed shape — under another
 * authenticator a `jwt` block is refused at both boundaries, so the optional
 * never hides an unparsed value. A factory registered under another name
 * reads its own sub-block and owes its own validation.
 */
export type OAuthConfig = {
	authenticator: string;
	jwt?: z.output<typeof OAuthJwtSchema>;
} & Record<string, unknown>;

/**
 * Zod schema for the HOCON-loaded application configuration. `.passthrough()`
 * on nested objects lets custom collector and factory configs add their own
 * fields without schema edits.
 */
export const AppConfigSchema = z.object({
	http: z
		.object({
			/**
			 * Bind address. Defaults to loopback — the verifier answers with
			 * authorization decisions, so a reachable port is a decision oracle.
			 * A container deployment sets `0.0.0.0` explicitly; that is the opt-in.
			 */
			hostname: z.string().default(DEFAULT_HOSTNAME),
			/**
			 * Port to bind: an integer from 1 to 65535. Unbounded, `port = "abc"`
			 * would reach `listen()` as NaN and `port = false` as 0, both of which
			 * bind an arbitrary free port.
			 */
			port: boundedNumber(NUMERIC_BOUNDS.port, "http"),
			pathPrefix: z.string().default(""),
			/**
			 * Optional shared credential the calling service must present.
			 * Configured means required; absent (or present with no `token`) means
			 * the decision endpoints accept any caller who can reach the port —
			 * which `createApp` warns about when the bind is not loopback.
			 *
			 * `token` has no default on purpose: a credential must come from the
			 * deployment, never from this file.
			 */
			callerAuth: z
				.object({
					header: z.string().min(1).default(DEFAULT_CALLER_AUTH_HEADER),
					// `.min(1)` and not `.optional()`-with-empty: `HTTP_CALLER_AUTH_TOKEN=`
					// substitutes an empty string, and booting unauthenticated because a
					// credential was exported empty would be a silent failure.
					token: z.string().min(1).optional(),
				})
				.optional(),
		})
		// The default object is taken verbatim — zod does not parse it back through
		// the shape — so it has to state every key that has no other source.
		.default(() => ({ hostname: DEFAULT_HOSTNAME, port: DEFAULT_HTTP_PORT, pathPrefix: "" })),
	/**
	 * The credential layer: how this verifier authenticates the subject before
	 * any rule runs. This module implements no OAuth flow; the namespace mirrors
	 * auth.provider's `oauth { jwt { … } }` (env: `OAUTH_JWT_*`), so one
	 * deployment addresses both sides of the token boundary with one
	 * vocabulary. The claim-level half of that boundary is specified in the
	 * umbrella's docs/claims-contract.md (o3co/auth); the keys below are the
	 * key-distribution half.
	 */
	oauth: z
		.object({
			/**
			 * Which token authenticator establishes the subject: `"jwt"`
			 * (the default, the built-in bearer-JWT path configured by `jwt`
			 * below) or a name a module registered. Read as `unknown` here so
			 * the one shared function decides what a well-formed name is at both
			 * boundaries; the `transform` below writes the resolved name back.
			 */
			authenticator: z.unknown().optional(),
			/**
			 * The built-in authenticator's block. Read as `unknown` here and parsed
			 * through `OAuthJwtSchema` in the transform below when `"jwt"` is
			 * selected; under another authenticator its presence is refused by the
			 * selection check, so both boundaries agree and nothing is carried unread.
			 */
			jwt: z.unknown().optional(),
		})
		// Another authenticator's own sub-block (`oauth.introspection { … }`)
		// rides along for its factory to read; the schema cannot know its shape.
		.passthrough()
		.transform((data, ctx) => {
			// The one reader for the selection, at both boundaries — `createApp`
			// calls the same function on hand-built configs (AGENTS.md,
			// "Two-Boundary Config Validation"). The resolved name is written
			// back so the parsed config carries the default the operator relied on.
			const selection = checkTokenAuthenticatorSelection(data);
			if (!selection.ok) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: selection.message,
					path: [selection.key],
				});
				return z.NEVER;
			}
			if (selection.name !== JWT_TOKEN_AUTHENTICATOR) {
				// `jwt` is absent here — the selection check refused a present one —
				// so the parsed type's `jwt?` reads truthfully: present means parsed.
				return { ...data, authenticator: selection.name } as OAuthConfig;
			}
			const jwt = OAuthJwtSchema.safeParse(data.jwt);
			if (!jwt.success) {
				for (const issue of jwt.error.issues) {
					ctx.addIssue({ ...issue, path: ["jwt", ...issue.path] });
				}
				return z.NEVER;
			}
			return { ...data, authenticator: selection.name, jwt: jwt.data } as OAuthConfig;
		}),
	attribute: z.object({
		collectors: z.array(collectorSchema),
	}),
	rule: z.object({
		collectors: z.array(collectorSchema),
		// Decision for a request that collects no rules. "deny" (default) keeps the
		// engine fail-closed; "allow" is an explicit per-deployment opt-out.
		onEmptyRuleSet: z.enum(["deny", "allow"]).default("deny"),
	}),
	resource: z
		.object({
			parser: z.string().default("DotNotationResourceParser"),
		})
		.default(() => ({ parser: "DotNotationResourceParser" })),
	verify: z
		.object({
			// Cap on `POST /verify/batch` entries. The batch endpoint exists so
			// filtering a list of N resources is one round trip; the cap keeps one
			// request from turning into an unbounded amount of pipeline work.
			// `createVerifyRouter` holds a hand-built config to the same bound.
			maxBatchSize: boundedNumber(NUMERIC_BOUNDS.maxBatchSize, "verify"),
			/*
			 * What one decision request may carry. Each limit is stated here,
			 * defaulted in `config/defaults.mts`, and held by
			 * `createVerifyRouter` through the same `resolveBound` for
			 * hand-built configs.
			 */
			maxBodyBytes: boundedNumber(NUMERIC_BOUNDS.maxBodyBytes, "verify"),
			maxResourceLength: boundedNumber(NUMERIC_BOUNDS.maxResourceLength, "verify"),
			maxActionLength: boundedNumber(NUMERIC_BOUNDS.maxActionLength, "verify"),
			maxContextEntries: boundedNumber(NUMERIC_BOUNDS.maxContextEntries, "verify"),
			maxContextValueLength: boundedNumber(NUMERIC_BOUNDS.maxContextValueLength, "verify"),
			/**
			 * Bounds on the collector fan-out both pipelines run for every
			 * decision. Collectors call databases and HTTP APIs; unbounded, one
			 * stalled collector would hold the decision open for as long as its
			 * socket did.
			 *
			 * `collectorTimeoutMs` is what one collector may take;
			 * `collectorDeadlineMs` is what the whole wave may take, which a
			 * per-collector budget cannot bound once collectors queue; and
			 * `collectorConcurrency` is how many run at once, which is what stops
			 * a slow dependency from being handed more simultaneous work as it
			 * slows. Read through `resolveBound` so `createApp` — which builds the
			 * pipelines, and accepts hand-built configs this schema never saw —
			 * refuses the same values in the same words.
			 *
			 * Exceeding any of them **denies**: see `CollectorTimeoutError` in
			 * core for why a partial answer is never the safe one.
			 */
			collectorTimeoutMs: boundedNumber(NUMERIC_BOUNDS.collectorTimeoutMs, "verify"),
			/** How long one asynchronous rule may take to answer; same bound as a collector. */
			ruleTimeoutMs: boundedNumber(NUMERIC_BOUNDS.ruleTimeoutMs, "verify"),
			/** How long all of a decision's asynchronous rules may take together; the rule phase's deadline. */
			evaluateDeadlineMs: boundedNumber(NUMERIC_BOUNDS.evaluateDeadlineMs, "verify"),
			collectorDeadlineMs: boundedNumber(NUMERIC_BOUNDS.collectorDeadlineMs, "verify"),
			collectorConcurrency: boundedNumber(NUMERIC_BOUNDS.collectorConcurrency, "verify"),
			/**
			 * How many of a batch's entries are decided at once. The
			 * three collector bounds above are per decision; this is what keeps
			 * one `POST /verify/batch` from multiplying them by `maxBatchSize`.
			 */
			batchConcurrency: boundedNumber(NUMERIC_BOUNDS.batchConcurrency, "verify"),
			/**
			 * Whether collectors receive the raw credential as
			 * `CollectorContext.credential`. `"never"` (default): verified
			 * claims only — the credential is replayable and a collector that
			 * logs its context would leak a live token. `"expose"`: for a
			 * project-side collector that calls a downstream API as the subject
			 * (token forwarding/exchange); the exposure is a stated, greppable
			 * config decision. An enum, not a boolean: `${?ENV}` hands this
			 * schema a string, and an enum takes it without a coercion path.
			 */
			credentialToCollectors: z.enum(["never", "expose"]).default("never"),
			/**
			 * Whether the decision response carries each rule's `evaluation` —
			 * its status and the policy revision. `"omit"` (default):
			 * the `decision` event carries it, the response does not. `"include"`:
			 * the response does too, for a consuming service that records which
			 * policy revision authorized an operation. Read through the shared
			 * check, not a bare `z.enum`, so `createVerifyRouter` refuses a
			 * hand-built config in the same words — see `evaluationInResponse.mts`.
			 */
			evaluationInResponse: z
				.unknown()
				.optional()
				.transform((value, ctx) => {
					const check = checkEvaluationInResponse(value);
					if (check.ok) return check.value;
					ctx.addIssue({ code: z.ZodIssueCode.custom, message: check.message });
					return z.NEVER;
				}),
		})
		/*
		 * Taken verbatim, like `http` above — zod does not parse a default back
		 * through the shape, so **every key of the block has to be repeated here**.
		 *
		 * A knob added to the shape above but not to this literal is silently
		 * `undefined` for every config with no `verify` block — the ordinary
		 * deployment shape, since an overlay config only repeats the sections it
		 * changes — and its bound stops applying. The test `AppConfigSchema — the
		 * verify block's default names every knob` walks the shape's own key list
		 * and fails on any key this literal does not answer for.
		 */
		.default(() => ({
			maxBatchSize: DEFAULT_MAX_BATCH_SIZE,
			maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
			maxResourceLength: DEFAULT_MAX_RESOURCE_LENGTH,
			maxActionLength: DEFAULT_MAX_ACTION_LENGTH,
			maxContextEntries: DEFAULT_MAX_CONTEXT_ENTRIES,
			maxContextValueLength: DEFAULT_MAX_CONTEXT_VALUE_LENGTH,
			collectorTimeoutMs: DEFAULT_COLLECTOR_TIMEOUT_MS,
			ruleTimeoutMs: DEFAULT_RULE_TIMEOUT_MS,
			evaluateDeadlineMs: DEFAULT_EVALUATE_DEADLINE_MS,
			collectorDeadlineMs: DEFAULT_COLLECT_DEADLINE_MS,
			collectorConcurrency: DEFAULT_COLLECTOR_CONCURRENCY,
			batchConcurrency: DEFAULT_BATCH_CONCURRENCY,
			credentialToCollectors: "never" as const,
			evaluationInResponse: DEFAULT_EVALUATION_IN_RESPONSE,
		})),
	// Defaulted (not shape-only): deployments mount an overlay config OVER the
	// template's application.conf, so a section the overlay does not repeat is
	// simply absent. `silent` is a threshold, not a level anything emits at.
	logging: z
		.object({
			level: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]).default("info"),
		})
		.default(() => ({ level: "info" as const })),
});

/** Type inferred from `AppConfigSchema`. Consumed by `createApp`. */
export type AppConfig = z.infer<typeof AppConfigSchema>;
