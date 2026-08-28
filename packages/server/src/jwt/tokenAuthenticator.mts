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
 *
 * #110 is what that warning was about. `jwtVerify` enforces `exp` and `nbf`
 * only when they are present, so a token minted — or forged — without `exp`
 * was accepted forever, in both modes. The fix is one pair of bounds resolved
 * once ({@link resolveJwtTimeClaimBounds}) and spent twice: as jose's
 * `requiredClaims` / `maxTokenAge` / `clockTolerance` on the verifying path,
 * and as the same three checks written out in {@link assertTimeClaims} on the
 * decode path. A change to either must land in both, or the two modes start
 * disagreeing about the same token.
 */

import type { EventLogger, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { decodeJwt, errors, type JWTPayload, jwtVerify } from "jose";
import { NUMERIC_BOUNDS, resolveBound } from "../config/bounds.mjs";

/**
 * Bounds on a presented token's own lifetime (#110), settable in either mode
 * because both modes enforce them.
 *
 * Each admits the string a HOCON env substitution delivers as well as a number,
 * for the same reason the JWKS fetch bounds in `jwt/jwks.mts` do: `createApp`
 * accepts hand-built config objects, and a consumer assembling one from
 * `process.env` supplies strings.
 */
export interface JwtTimeClaimConfig {
	/**
	 * Ceiling on `now - iat`, in seconds. Positive integer; defaults to
	 * `DEFAULT_MAX_TOKEN_AGE_SECONDS`. Setting it makes `iat` required.
	 */
	maxTokenAgeSeconds?: number | string;
	/**
	 * Skew allowance applied to every time-claim comparison, in seconds. Integer
	 * from 0 to `MAX_CLOCK_TOLERANCE_SECONDS`; defaults to 0.
	 */
	clockToleranceSeconds?: number | string;
}

/**
 * The resolved bounds, spelled the way jose's claim-verification options name
 * them so the verifying path can hand them straight over and the decode path
 * has one obvious thing to mirror.
 */
export interface JwtTimeClaimBounds {
	/** jose `maxTokenAge`, in seconds. */
	maxTokenAge: number;
	/** jose `clockTolerance`, in seconds. */
	clockTolerance: number;
}

/**
 * Claims every token must carry, whatever else the config says (#110).
 *
 * `exp` is here rather than in a knob because a token with no stated expiry is
 * a permanent credential, and a fail-closed authorization service must not
 * depend on the issuer's discipline for that. `iat` is required as a
 * consequence of {@link JwtTimeClaimBounds.maxTokenAge} always being set —
 * jose adds it to its own presence check for the same reason. RFC 9068 §2.2
 * requires both of an access token, so this asks nothing of a conforming issuer.
 */
const REQUIRED_CLAIMS = ["exp"] as const;

/**
 * Resolves the time-claim bounds, falling back to the defaults for anything the
 * config omits, and refusing a stated bound that is not a whole number of
 * seconds in range. Hand-built configs never went through `AppConfigSchema`, so
 * the defaults and the validation both have to hold here too: an unparsed
 * string handed to jose is silently ignored in favour of *its* default, which
 * for `maxTokenAge` means no ceiling at all.
 *
 * The bounds themselves live in `config/bounds.mts` and are the very specs
 * `AppConfigSchema` reads a config file through (#157), so the two boundaries
 * cannot diverge on what a knob admits or on how it says so.
 *
 * @param path Config path of the JWT block at the calling boundary. The router
 * sees it as `jwt`; `createApp` passes `oauth.jwt`, the key the operator wrote.
 */
export function resolveJwtTimeClaimBounds(
	config: JwtTimeClaimConfig,
	path = "jwt",
): JwtTimeClaimBounds {
	return {
		maxTokenAge: resolveBound(config.maxTokenAgeSeconds, NUMERIC_BOUNDS.maxTokenAgeSeconds, path),
		clockTolerance: resolveBound(
			config.clockToleranceSeconds,
			NUMERIC_BOUNDS.clockToleranceSeconds,
			path,
		),
	};
}

/**
 * JWT parameters used when signature validation is on. Every field a resource
 * server must check per RFC 9068 §4 is required here, so a deployment cannot
 * end up verifying the signature alone.
 */
export interface VerifyingJwtConfig extends JwtTimeClaimConfig {
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
 * Test-only shape: the token is decoded, never signature-verified. Its time
 * claims are still enforced in full (#106, #110) — `exp` and `iat` required,
 * `nbf` honoured, and the same age ceiling the verifying mode applies. On the
 * wire this shape is selected by the single self-documenting key
 * `oauth.jwt.mode = "insecure-decode"` (#134);
 * internally the interlock stays a two-key literal, and the acknowledgment is
 * re-checked at construction time — so wiring the router directly with a
 * hand-built config is not a way around the explicit consent `createApp`
 * demands.
 */
export interface DecodingJwtConfig extends JwtTimeClaimConfig {
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

/**
 * True for a non-empty string, and nothing else. What `tokenType` is held to:
 * the accepted `typ` header is a single value, `z.string()` at the schema and
 * `tokenType: string` on {@link VerifyingJwtConfig}, where `issuer` and
 * `audience` may be lists because jose accepts lists for them.
 *
 * The distinction is load-bearing (#164). While `tokenType` shared the
 * list-tolerant {@link isPresent} with the other two, a hand-built
 * `tokenType: ["at+jwt"]` passed a guard the schema refuses — and the
 * deployment then booted and rejected *every* token, because jose lowercases
 * the `typ` option to compare it and threw a bare `TypeError` off the array on
 * each request. That escapes as a non-`JOSEError`, so
 * {@link isVerificationUnavailable} judged a config typo to be an
 * infrastructure outage and logged it as `jwt_verification_unavailable` — the
 * line #107 added to mean the opposite of an operator mistake.
 */
function isPresentString(value: unknown): boolean {
	return typeof value === "string" && value !== "";
}

/** True for a non-empty string or a non-empty array of non-empty strings. */
function isPresent(value: unknown): boolean {
	return Array.isArray(value)
		? value.length > 0 && value.every((v) => isPresentString(v))
		: isPresentString(value);
}

/**
 * Construction-time guard for the two JWT config invariants. Fails fast rather
 * than letting a misbuilt config accept tokens:
 *
 * 1. `issuer`, `audience` and `tokenType` must be present whenever `validate`
 *    is true (RFC 9068 §4): a deployment must never verify the signature alone.
 *    `issuer` and `audience` take a non-empty string or a non-empty array of
 *    them; `tokenType` takes a non-empty string only — see
 *    {@link isPresentString}.
 * 2. `validate: false` requires the explicit `allowInsecureDecode: true`
 *    acknowledgment (#106): one mistyped flag must never be enough to disable
 *    all signature verification.
 *
 * Both boundaries enforce these — see AGENTS.md, "Two-Boundary Config
 * Validation" — and this is the pair named there as a departure from it, the
 * one place the two boundaries cannot share a check function. `AppConfigSchema`
 * reads the wire spelling: the presence checks via `superRefine`, the
 * decode-only consent via the `mode` enum whose `"insecure-decode"` value is
 * itself the acknowledgment (#134), every issue reported at once with zod
 * paths. This guard reads the internal two-key interlock, because #134 split
 * the two spellings. There is no one shape to check from both sides.
 *
 * What holds the two implementations in step is the burden the departure owes:
 * `__tests__/jwtConfigTwoBoundaryParity.test.mts` writes one configuration in
 * both spellings and asserts the two boundaries reach the same verdict and name
 * the same key. Add an invariant here and it is a row there, not a new test.
 * The one row where they deliberately differ is `tokenType`'s absence, carved
 * out and argued for in that AGENTS.md section.
 */
export function assertVerifyRouterJwtConfig<T extends UncheckedJwtConfig>(
	jwt: T,
	context: JwtConfigErrorContext = { caller: "createTokenAuthenticator", path: "jwt" },
): asserts jwt is T & AssertedJwtConfig {
	const { caller, path } = context;
	if (jwt.validate) {
		const verifyCondition = context.verifyCondition ?? `${path}.validate is true`;
		// One check per field rather than one for all three: `typ` is a single
		// value where `iss`/`aud` are lists (#164). Order matches the schema's
		// `superRefine`, so a config with more than one missing key sends both
		// boundaries to the same one first.
		const presence = [
			["issuer", isPresent(jwt.issuer)],
			["audience", isPresent(jwt.audience)],
			["tokenType", isPresentString(jwt.tokenType)],
		] as const;
		for (const [field, present] of presence) {
			if (!present) {
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

/** Time claims the decode path reads, in the order `jwtVerify` type-checks them. */
type TimeClaim = "iat" | "nbf" | "exp";

/**
 * Reads one time claim the way `jwtVerify` does: absent (allowed only where
 * jose allows it, and the caller has already ruled that out for the required
 * ones) or numeric. A present non-numeric value is always a rejection, `iat`
 * included — jose type-checks it whether or not anything consumes it.
 */
function readTimeClaim(payload: JWTPayload, claim: TimeClaim): number | undefined {
	const value = payload[claim];
	if (value === undefined) {
		return undefined;
	}
	if (typeof value !== "number") {
		throw new errors.JWTClaimValidationFailed(
			`"${claim}" claim must be a number`,
			payload,
			claim,
			"invalid",
		);
	}
	return value;
}

/**
 * Time-claim checks for the decode-only path (#106, #110). `decodeJwt`
 * performs no validation at all, so the authenticator enforces the token's own
 * lifetime here, restating `jwtVerify`'s semantics, error classes and rejection
 * order by hand: presence first (`iat` before `exp`, jose's own order), then
 * `nbf` against `now + tolerance`, `exp` against `now - tolerance`, and finally
 * the age of the token against {@link JwtTimeClaimBounds.maxTokenAge}, which
 * also refuses an `iat` in the future. Skipping the signature is an
 * (acknowledged, test-only) trust decision about the issuer; honouring an
 * expired — or unexpiring — token is simply wrong in every mode.
 *
 * `bounds` is a required argument rather than a defaulted one on purpose: the
 * whole failure #110 records is a validation option that reached `jwtVerify`
 * and never reached here, and a parameter that quietly defaults is how that
 * happens again.
 */
export function assertTimeClaims(payload: JWTPayload, bounds: JwtTimeClaimBounds): void {
	const now = Math.floor(Date.now() / 1000);
	const { clockTolerance, maxTokenAge } = bounds;

	// Presence for every required claim first, before any of them is read —
	// jose's own order, and `iat` leads it because `maxTokenAge` is always set,
	// which is what makes `iat` mandatory alongside the `exp` #110 requires.
	for (const claim of ["iat", ...REQUIRED_CLAIMS] as const) {
		if (!Object.hasOwn(payload, claim)) {
			throw new errors.JWTClaimValidationFailed(
				`missing required "${claim}" claim`,
				payload,
				claim,
				"missing",
			);
		}
	}

	const iat = readTimeClaim(payload, "iat") as number;
	const nbf = readTimeClaim(payload, "nbf");
	if (nbf !== undefined && nbf > now + clockTolerance) {
		throw new errors.JWTClaimValidationFailed(
			'"nbf" claim timestamp check failed',
			payload,
			"nbf",
			"check_failed",
		);
	}

	const exp = readTimeClaim(payload, "exp") as number;
	if (exp <= now - clockTolerance) {
		throw new errors.JWTExpired(
			'"exp" claim timestamp check failed',
			payload,
			"exp",
			"check_failed",
		);
	}

	const age = now - iat;
	if (age - clockTolerance > maxTokenAge) {
		throw new errors.JWTExpired(
			'"iat" claim timestamp check failed (too far in the past)',
			payload,
			"iat",
			"check_failed",
		);
	}
	if (age < 0 - clockTolerance) {
		throw new errors.JWTClaimValidationFailed(
			'"iat" claim timestamp check failed (it should be in the past)',
			payload,
			"iat",
			"check_failed",
		);
	}
}

/**
 * Outcome of authenticating a caller. On failure the authenticator names the
 * machine-readable code and the caller-safe message; what HTTP status that
 * maps to (401 for all of them today) is the route's concern, not this
 * module's.
 *
 * `subject` is core's neutral `SubjectAttributes` bag, and this module is the
 * one edge that populates it (#170): the verified JWT's claims are spread in,
 * so under this server the bag's keys are the token's claims. Core never
 * learns that — the claim vocabulary ends here and in the collectors that
 * narrow it back out.
 */
export type AuthenticationResult =
	| { ok: true; subject: SubjectAttributes; credential: string }
	| { ok: false; code: "missing_token" | "unsupported_scheme" | "invalid_token"; message: string };

/** Authenticates one `Authorization` header value into verified subject attributes. */
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
	// Resolved once, at construction: an unusable bound must fail here rather
	// than per request, and both branches below read the same resolved values —
	// which is the only reason the two paths cannot drift on them.
	const { maxTokenAge, clockTolerance } = resolveJwtTimeClaimBounds(jwt);

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
						// #110. `requiredClaims` is what turns exp from "checked when
						// present" into "checked"; `maxTokenAge` bounds a token whose
						// issuer chose a distant exp, and requires `iat` as a side
						// effect. The decode branch below restates all three by hand.
						requiredClaims: [...REQUIRED_CLAIMS],
						maxTokenAge,
						clockTolerance,
					});
					decoded = result.payload;
				} else {
					decoded = decodeJwt(token);
					assertTimeClaims(decoded, { maxTokenAge, clockTolerance });
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

			// The JWT→subject mapping edge (#170): the verified claims are spread
			// into the neutral bag here, plus `authScheme` — the `Authorization`
			// scheme the token arrived under, as the caller wrote it (reported,
			// not compared, so its casing is not normalized). `authScheme`, not
			// `tokenType` (#158): `jwt.tokenType` a few lines up is the accepted
			// `typ` header, an entirely different thing, and the two shared a name
			// in the one module that mentions both.
			//
			// #175: the raw credential rides the RESULT, not the subject bag. The
			// bag reaches every collector; the credential reaches a collector
			// only when the route was composed with `credentialToCollectors:
			// "expose"` — that gate is the route's, so this module hands the
			// credential back separately and attaches nothing to the claims.
			return { ok: true, subject: { ...decoded, authScheme: scheme }, credential: token };
		},
	};
}
