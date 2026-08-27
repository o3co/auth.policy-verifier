// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";
import { checkJwksUri } from "../jwt/jwks.mjs";
import {
	DEFAULT_CALLER_AUTH_HEADER,
	DEFAULT_CLOCK_TOLERANCE_SECONDS,
	DEFAULT_HOSTNAME,
	DEFAULT_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_JWKS_COOLDOWN_MS,
	DEFAULT_JWKS_TIMEOUT_MS,
	DEFAULT_MAX_BATCH_SIZE,
	DEFAULT_MAX_TOKEN_AGE_SECONDS,
	MAX_CLOCK_TOLERANCE_SECONDS,
} from "./defaults.mjs";

/**
 * Migration message for the wire keys removed in #134. Emitted by the schema
 * for parsed configs and by `createApp` for hand-built ones, so an operator
 * upgrading across the break always gets the same actionable pointer instead
 * of a puzzling "issuer is required" from a silently-defaulted mode.
 */
export const JWT_MODE_MIGRATION_MESSAGE =
	'oauth.jwt.validate/allowInsecureDecode were replaced by oauth.jwt.mode; set mode = "verify" or the explicit "insecure-decode"';

const collectorSchema = z
	.object({
		collector: z.string(),
	})
	.passthrough();

/**
 * Zod schema for the HOCON-loaded application configuration. Validates the
 * shape of `http`, `oauth.jwt`, `attribute.collectors`, `rule.collectors`, and
 * `resource.parser`. `.passthrough()` on nested objects lets custom collector
 * and factory configs add their own fields without schema edits.
 *
 * Built-in JWT algorithms (HS256 / RS256 / ES256 / EdDSA) carry extra
 * `superRefine` validation for their required key material. Unknown algorithm
 * names pass schema validation and are expected to validate themselves in
 * their `KeyResolverFactory`.
 */
export const AppConfigSchema = z.object({
	http: z
		.object({
			/**
			 * Bind address. Defaults to loopback (#108) — the verifier answers with
			 * authorization decisions, so a reachable port is a decision oracle.
			 * A container deployment sets `0.0.0.0` explicitly; that is the opt-in.
			 */
			hostname: z.string().default(DEFAULT_HOSTNAME),
			port: z.coerce.number().default(3000),
			pathPrefix: z.string().default(""),
			/**
			 * Optional shared credential the calling service must present (#108).
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
					// credential was exported empty is the silent failure #108 is about.
					token: z.string().min(1).optional(),
				})
				.optional(),
		})
		.default(() => ({ hostname: DEFAULT_HOSTNAME, port: 3000, pathPrefix: "" })),
	oauth: z.object({
		// Algorithm names are free-form strings so user-registered algorithms can be selected
		// from config without editing the schema enum. Built-in algorithms keep schema-level
		// validation below (via superRefine) so misconfigurations fail at config-parse time.
		// Custom algorithms are expected to validate their own config in their factory.
		jwt: z
			.object({
				algorithm: z.string().default("HS256"),
				secret: z.string().optional(),
				/**
				 * JWKS endpoint for the asymmetric algorithms. Must be https — or
				 * http on a loopback host, the development carve-out documented in
				 * `jwt/jwks.mts` (#109). The scheme is checked in `superRefine`
				 * below so a plaintext endpoint fails at config-parse time, at boot,
				 * rather than at the first request that misses the key cache.
				 */
				jwksUri: z.string().optional(),
				// Bounds on the JWKS fetch, which happens inside a verify request
				// whenever key resolution misses the cache (#109). Coerced because a
				// HOCON env substitution delivers strings.
				jwksTimeoutMs: z.coerce.number().int().positive().default(DEFAULT_JWKS_TIMEOUT_MS),
				// Zero is a valid cooldown — "refetch on every miss", at the cost of
				// letting an attacker-chosen `kid` drive fetches at the provider.
				jwksCooldownMs: z.coerce.number().int().nonnegative().default(DEFAULT_JWKS_COOLDOWN_MS),
				jwksCacheMaxAgeMs: z.coerce
					.number()
					.int()
					.positive()
					.default(DEFAULT_JWKS_CACHE_MAX_AGE_MS),
				publicKey: z.string().optional(),
				publicKeyPath: z.string().optional(),
				/**
				 * How the verifier treats bearer tokens (#134). `"verify"` (the default)
				 * fully verifies signature, iss, aud and typ; `"insecure-decode"` is the
				 * test-only mode that decodes without signature verification (`exp` /
				 * `nbf` are still enforced at request time). The value itself is the
				 * consent: an accidental env-var flip can produce a stray boolean, but
				 * never the literal string `"insecure-decode"` — which preserves the
				 * intent of #106's double opt-in (one mistyped variable must never be
				 * able to disable all token verification) in a single explicit knob.
				 * The former pair `validate` / `allowInsecureDecode` is rejected below
				 * with a migration message.
				 */
				mode: z.enum(["verify", "insecure-decode"]).default("verify"),
				// RFC 9068 §4 — a resource server validates iss and aud, not just the
				// signature. Both are required whenever mode is "verify" (see superRefine).
				issuer: z.union([z.string(), z.array(z.string())]).optional(),
				audience: z.union([z.string(), z.array(z.string())]).optional(),
				// Accepted `typ` header. `at+jwt` is the RFC 9068 access-token type; pinning
				// it rejects id_tokens, refresh tokens and logout tokens signed with the same key.
				tokenType: z.string().default("at+jwt"),
				/**
				 * Bounds on a presented token's own lifetime (#110). Both apply in
				 * every mode: `insecure-decode` restates them by hand, so a
				 * deployment cannot end up with the two modes disagreeing about the
				 * same token. Coerced because a HOCON env substitution delivers strings.
				 *
				 * `maxTokenAgeSeconds` is the ceiling on `now - iat` — what refuses a
				 * token whose issuer set `exp` years out — and setting it makes `iat`
				 * required (RFC 9068 §2.2 requires it anyway). `exp` itself is
				 * required unconditionally and has no knob: a knob to accept tokens
				 * that never expire is the bug, not the setting.
				 */
				maxTokenAgeSeconds: z.coerce
					.number()
					.int()
					.positive()
					.default(DEFAULT_MAX_TOKEN_AGE_SECONDS),
				/**
				 * Skew allowance on every time-claim comparison. Bounded above
				 * because tolerance lengthens the accepted life of every token the
				 * deployment sees — an unbounded knob is a way to spell "expiry
				 * optional" without writing it down. `60` matches the skew the paired
				 * provider allows and is the value to reach for when the issuer and
				 * the verifier keep separate clocks.
				 */
				clockToleranceSeconds: z.coerce
					.number()
					.int()
					.min(0)
					.max(MAX_CLOCK_TOLERANCE_SECONDS)
					.default(DEFAULT_CLOCK_TOLERANCE_SECONDS),
			})
			.passthrough()
			.superRefine((data, ctx) => {
				// Hard-error on the wire keys removed in #134. `.passthrough()` would
				// otherwise let them ride along silently — and a decode-only config
				// written for 0.x (`validate=false` + `allowInsecureDecode=true`) would
				// be reinterpreted as the defaulted verify mode, failing with an
				// unrelated "issuer is required" instead of migration guidance.
				let hasStaleKey = false;
				for (const staleKey of ["validate", "allowInsecureDecode"] as const) {
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
				if (data.mode === "insecure-decode") {
					// Decode-only mode: no signature check (exp/nbf are still enforced
					// at request time, but nothing else is). The mode string itself is
					// the explicit consent (#134) — see the `mode` doc comment.
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
				const isBuiltinAsymmetric = ["RS256", "ES256", "EdDSA"].includes(data.algorithm);
				if (isBuiltinAsymmetric && !data.jwksUri && !data.publicKey && !data.publicKeyPath) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: `jwksUri or publicKey/publicKeyPath is required for ${data.algorithm}`,
					});
				}
				// Transport security for the key source (#109): a plaintext JWKS
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
			}),
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
			maxBatchSize: z.coerce.number().int().positive().default(DEFAULT_MAX_BATCH_SIZE),
		})
		.default(() => ({ maxBatchSize: DEFAULT_MAX_BATCH_SIZE })),
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
