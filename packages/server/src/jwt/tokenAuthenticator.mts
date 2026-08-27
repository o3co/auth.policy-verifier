// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Bearer-token authentication for the verify endpoints: the JWT config union,
 * its construction-time invariants, and the request-time token checks.
 *
 * The verifying path (`jwtVerify`) and the decode-only path
 * (`decodeJwt` + `assertTimeClaims`) are two halves of one contract and are
 * deliberately co-located: the decode path restates by hand every request-time
 * check that survives without key material (today: the time claims), so any
 * validation option threaded to the verifying path must be weighed — and
 * usually threaded — into the decode path as well. Keeping both paths in this
 * one module is what keeps that coupling visible.
 */

import type { EventLogger, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { decodeJwt, errors, type JWTPayload, jwtVerify } from "jose";

/**
 * JWT parameters used when signature validation is on. Every field a resource
 * server must check per RFC 9068 §4 is required here, so a deployment cannot
 * end up verifying the signature alone.
 */
export interface VerifyingJwtConfig {
	validate: true;
	// The `key` is produced by a KeyResolverFactory; its concrete type depends on
	// the algorithm (e.g. KeyObject for HS256, JWTVerifyGetKey for JWKS, etc.).
	// The authenticator narrows it via cast when calling jwtVerify.
	key: unknown;
	algorithms: string[];
	/** Issuer(s) this deployment accepts. A token minted by anyone else is rejected. */
	issuer: string | string[];
	/** Audience identifying this resource server. A token minted for another service is rejected. */
	audience: string | string[];
	/**
	 * Accepted `typ` header — `"at+jwt"` for RFC 9068 access tokens. An `application/`
	 * prefix on either side is ignored when comparing. Pinning it is what keeps an
	 * `id_token`, refresh token or logout token signed with the same key from passing.
	 */
	tokenType: string;
}

/**
 * Test-only shape: the token is decoded, never signature-verified. Its `exp` /
 * `nbf` claims are still enforced (#106). On the wire this shape is selected by
 * the single self-documenting key `oauth.jwt.mode = "insecure-decode"` (#134);
 * internally the interlock stays a two-key literal, and the acknowledgment is
 * re-checked at construction time — so wiring the router directly with a
 * hand-built config is not a way around the explicit consent `createApp`
 * demands.
 */
export interface DecodingJwtConfig {
	validate: false;
	allowInsecureDecode: true;
}

/** JWT half of `VerifyRouterConfig`, discriminated on `validate`. */
export type VerifyRouterJwtConfig = VerifyingJwtConfig | DecodingJwtConfig;

/**
 * The invariant-carrying subset of a JWT config, deliberately loose:
 * {@link assertVerifyRouterJwtConfig} exists precisely for objects whose static
 * types cannot be trusted, so its input type must admit them.
 */
export interface UncheckedJwtConfig {
	validate: boolean;
	issuer?: string | string[];
	audience?: string | string[];
	tokenType?: string;
	allowInsecureDecode?: boolean;
}

/**
 * What {@link assertVerifyRouterJwtConfig} proves about the config it accepted.
 * Intersecting rather than replacing the input type keeps whatever else the
 * caller's config carries (key material, algorithm names).
 */
export type AssertedJwtConfig =
	| { validate: true; issuer: string | string[]; audience: string | string[]; tokenType: string }
	| { validate: false; allowInsecureDecode: true };

/**
 * Where a guard failure is reported from, for operator-facing error messages:
 * the boundary the operator actually called and the config path as they wrote
 * it (`createApp` sees the JWT block at `oauth.jwt`, the router at `jwt`).
 */
export interface JwtConfigErrorContext {
	/** Boundary named in the message, e.g. `"createApp"`. */
	caller: string;
	/** Config path of the JWT block at that boundary, e.g. `"oauth.jwt"`. */
	path: string;
	/**
	 * How the operator selects verifying mode at this boundary, completing the
	 * sentence "<field> is required when <verifyCondition>". The router's
	 * internal union is discriminated on `validate`, so the default is
	 * `"<path>.validate is true"`; `createApp` passes the wire spelling
	 * `oauth.jwt.mode is "verify"`, because `validate` is no longer a wire key
	 * (#134) and the message must name what the operator actually wrote.
	 */
	verifyCondition?: string;
}

/** True for a non-empty string or a non-empty array of non-empty strings. */
function isPresent(value: string | string[] | undefined): boolean {
	return Array.isArray(value)
		? value.length > 0 && value.every((v) => typeof v === "string" && v !== "")
		: typeof value === "string" && value !== "";
}

/**
 * Construction-time guard for the two JWT config invariants. Fails fast rather
 * than letting a misbuilt config accept tokens:
 *
 * 1. `issuer`, `audience` and `tokenType` must be present — a non-empty string
 *    or a non-empty array of non-empty strings — whenever `validate` is true
 *    (RFC 9068 §4): a deployment must never verify the signature alone.
 * 2. `validate: false` requires the explicit `allowInsecureDecode: true`
 *    acknowledgment (#106): one mistyped flag must never be enough to disable
 *    all signature verification.
 *
 * Division of labor with `AppConfigSchema`: the schema enforces the same
 * invariants for schema-validated configs at config-parse time — the RFC 9068
 * presence checks via `superRefine`, the decode-only consent via the `mode`
 * enum whose `"insecure-decode"` value is itself the acknowledgment (#134) —
 * reporting every issue at once with zod paths. This guard is the runtime
 * enforcement for hand-built configs that never went through the schema — a
 * JavaScript caller can reach `createApp` or `createVerifyRouter` with fields
 * missing even though the TypeScript shapes require them. Both stay: the
 * schema serves config files, the guard serves the API boundary.
 */
export function assertVerifyRouterJwtConfig<T extends UncheckedJwtConfig>(
	jwt: T,
	context: JwtConfigErrorContext = { caller: "createTokenAuthenticator", path: "jwt" },
): asserts jwt is T & AssertedJwtConfig {
	const { caller, path } = context;
	if (jwt.validate) {
		const verifyCondition = context.verifyCondition ?? `${path}.validate is true`;
		for (const field of ["issuer", "audience", "tokenType"] as const) {
			if (!isPresent(jwt[field])) {
				throw new Error(
					`${caller}: ${path}.${field} is required when ${verifyCondition} (RFC 9068 §4)`,
				);
			}
		}
	} else if (jwt.allowInsecureDecode !== true) {
		throw new Error(
			`${caller}: ${path}.validate=false disables ALL signature verification (test-only); ` +
				`set ${path}.allowInsecureDecode=true to acknowledge, or use a verifying config`,
		);
	}
}

/**
 * True when token verification could not be attempted or completed for reasons
 * unrelated to the presented token — the situation an operator must be able to
 * tell apart from a bad token (#107: a JWKS outage flips the whole fleet to
 * 401-deny while the verifier's own logs stay empty).
 *
 * Infrastructure side: a JWKS fetch timeout, a malformed JWKS document, a bare
 * `JOSEError` (`ERR_JOSE_GENERIC` — jose reserves the base class for the JWKS
 * fetch path: its only two throw sites are a non-200 JWKS response and a body
 * that fails to parse as JSON), or any non-jose error escaping `jwtVerify`
 * (fetch/DNS failures from the remote key getter, a broken key resolver).
 * Every subclass jose throws about the token itself is judged token-side —
 * deliberately including `JWKSNoMatchingKey`, because the `kid` that failed to
 * match is attacker-controllable and must not open an error-level log-flooding
 * channel; its `err.code` in the warn line still identifies a stale-JWKS
 * rotation problem.
 */
export function isVerificationUnavailable(cause: unknown): boolean {
	if (!(cause instanceof errors.JOSEError)) {
		return true;
	}
	return (
		cause instanceof errors.JWKSTimeout ||
		cause instanceof errors.JWKSInvalid ||
		cause.code === "ERR_JOSE_GENERIC"
	);
}

/**
 * `exp` / `nbf` checks for the decode-only path (#106). `decodeJwt` performs
 * no validation at all, so the authenticator enforces the token's own lifetime
 * with `jwtVerify`'s semantics and error classes: reject a numeric `exp` in
 * the past or a numeric `nbf` in the future, reject a present non-numeric
 * value for any time claim (`iat` included — `jwtVerify` type-checks it
 * unconditionally), tolerate absence, zero clock tolerance. Skipping the
 * signature is an (acknowledged, test-only) trust decision about the issuer;
 * honouring an expired token is simply wrong in every mode.
 */
export function assertTimeClaims(payload: JWTPayload): void {
	const now = Math.floor(Date.now() / 1000);
	if (payload.iat !== undefined && typeof payload.iat !== "number") {
		throw new errors.JWTClaimValidationFailed(
			'"iat" claim must be a number',
			payload,
			"iat",
			"invalid",
		);
	}
	if (payload.nbf !== undefined) {
		if (typeof payload.nbf !== "number") {
			throw new errors.JWTClaimValidationFailed(
				'"nbf" claim must be a number',
				payload,
				"nbf",
				"invalid",
			);
		}
		if (payload.nbf > now) {
			throw new errors.JWTClaimValidationFailed(
				'"nbf" claim timestamp check failed',
				payload,
				"nbf",
				"check_failed",
			);
		}
	}
	if (payload.exp !== undefined) {
		if (typeof payload.exp !== "number") {
			throw new errors.JWTClaimValidationFailed(
				'"exp" claim must be a number',
				payload,
				"exp",
				"invalid",
			);
		}
		if (payload.exp <= now) {
			throw new errors.JWTExpired(
				'"exp" claim timestamp check failed',
				payload,
				"exp",
				"check_failed",
			);
		}
	}
}

/**
 * Outcome of authenticating a caller. On failure the authenticator names the
 * machine-readable code and the caller-safe message; what HTTP status that
 * maps to (401 for all of them today) is the route's concern, not this
 * module's.
 */
export type AuthenticationResult =
	| { ok: true; payload: VerifierPayload }
	| { ok: false; code: "missing_token" | "unsupported_scheme" | "invalid_token"; message: string };

/** Authenticates one `Authorization` header value into a verified payload. */
export interface TokenAuthenticator {
	authenticate(authorizationHeader: string | undefined): Promise<AuthenticationResult>;
}

/**
 * Builds the bearer-token authenticator shared by the verify endpoints:
 * extracts the bearer token and runs it down the path the config selects.
 * Runs {@link assertVerifyRouterJwtConfig} first, so an invalid hand-built
 * config fails at construction rather than accept tokens.
 */
export function createTokenAuthenticator(
	jwt: VerifyRouterJwtConfig,
	logger: EventLogger,
): TokenAuthenticator {
	assertVerifyRouterJwtConfig(jwt);

	return {
		async authenticate(authorizationHeader: string | undefined): Promise<AuthenticationResult> {
			if (!authorizationHeader) {
				return {
					ok: false,
					code: "missing_token",
					message: "Authorization header is missing",
				};
			}

			const authHeader = authorizationHeader.trim();
			const spaceIndex = authHeader.indexOf(" ");
			const scheme = spaceIndex > 0 ? authHeader.slice(0, spaceIndex) : authHeader;
			const token = spaceIndex > 0 ? authHeader.slice(spaceIndex + 1).trim() : undefined;

			if (scheme.toLowerCase() !== "bearer") {
				return {
					ok: false,
					code: "unsupported_scheme",
					message: `Unsupported authorization scheme: ${scheme}`,
				};
			}
			if (!token) {
				return {
					ok: false,
					code: "missing_token",
					message: "Authorization header is missing",
				};
			}

			let decoded: JWTPayload;
			try {
				// The coupled pair this module exists for: every validation option
				// handed to jwtVerify below must be re-considered for the decode
				// branch, which has to restate by hand whatever still applies
				// without key material (see assertTimeClaims).
				if (jwt.validate) {
					// key is either a static key or a JWKS get-key function; both satisfy jwtVerify overloads
					const result = await jwtVerify(token, jwt.key as Parameters<typeof jwtVerify>[1], {
						algorithms: jwt.algorithms,
						issuer: jwt.issuer,
						audience: jwt.audience,
						typ: jwt.tokenType,
					});
					decoded = result.payload;
				} else {
					decoded = decodeJwt(token);
					assertTimeClaims(decoded);
				}
			} catch (cause) {
				// Same invalid_token rejection either way — the caller is
				// unauthenticated regardless — but the log line is what lets the
				// operator tell a provider outage from a bad token.
				if (isVerificationUnavailable(cause)) {
					logger.error({ err: cause }, "jwt_verification_unavailable");
				} else {
					logger.warn({ err: cause }, "jwt_token_rejected");
				}
				return {
					ok: false,
					code: "invalid_token",
					message: "Invalid token",
				};
			}

			return { ok: true, payload: { ...decoded, token, tokenType: scheme } };
		},
	};
}
