// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Unit tests for the construction-time JWT config guard (#132).
 *
 * The guard is the single runtime enforcement point for the two config
 * invariants ("iss/aud/typ present when validating", "decode-only requires the
 * explicit acknowledgment"). Before the extraction the same invariants were
 * restated in three places, and the `createApp` copy had drifted: a bare falsy
 * check that accepted `issuer: []` and `issuer: [""]` and never looked at
 * `tokenType`. The drift cases are pinned here so the one guard can never
 * regress to the weak form.
 */
import { errors, type JWTPayload, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	assertTimeClaims,
	assertVerifyRouterJwtConfig,
	createTokenAuthenticator,
	type JwtTimeClaimBounds,
	resolveJwtTimeClaimBounds,
	type VerifyRouterJwtConfig,
} from "#/jwt/tokenAuthenticator.mjs";

const VALID_VERIFYING = {
	validate: true as const,
	key: new TextEncoder().encode("test-secret"),
	algorithms: ["HS256"],
	issuer: "https://issuer.test",
	audience: "https://api.test",
	tokenType: "at+jwt",
};

/**
 * The same config with a key long enough to actually sign with — HS256 wants at
 * least the hash width, and `VALID_VERIFYING`'s short key exists only to be
 * passed to the guard, which never uses it.
 */
const SIGNING_KEY = new TextEncoder().encode("0".repeat(32));
const SIGNING_CONFIG = { ...VALID_VERIFYING, key: SIGNING_KEY };

/** A token this deployment accepts: right issuer, audience, `typ` and time claims. */
async function signToken(claims: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "user-1", ...claims })
		.setProtectedHeader({ alg: "HS256", typ: VALID_VERIFYING.tokenType })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(VALID_VERIFYING.issuer)
		.setAudience(VALID_VERIFYING.audience)
		.sign(SIGNING_KEY);
}

describe("assertVerifyRouterJwtConfig — verifying configs (RFC 9068 §4 presence invariant)", () => {
	it("accepts a complete verifying config", () => {
		expect(() => assertVerifyRouterJwtConfig(VALID_VERIFYING)).not.toThrow();
	});

	it("accepts array-valued issuer and audience with non-empty entries", () => {
		expect(() =>
			assertVerifyRouterJwtConfig({
				...VALID_VERIFYING,
				issuer: ["https://issuer-a.test", "https://issuer-b.test"],
				audience: ["https://api.test"],
			}),
		).not.toThrow();
	});

	it("rejects a missing issuer", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, issuer: undefined })).toThrow(
			/jwt\.issuer is required when jwt\.validate is true/,
		);
	});

	it("rejects an empty-string issuer", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, issuer: "" })).toThrow(
			/jwt\.issuer is required/,
		);
	});

	// Drift case: the drifted createApp copy's bare `!issuer` check (now a call
	// to this guard) accepted [] — an empty array is truthy, yet pins no issuer.
	it("rejects an empty issuer array", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, issuer: [] })).toThrow(
			/jwt\.issuer is required/,
		);
	});

	// Drift case: [""] is a non-empty array, but its only entry pins nothing.
	it("rejects an issuer array containing an empty string", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, issuer: [""] })).toThrow(
			/jwt\.issuer is required/,
		);
	});

	it("rejects a missing audience", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, audience: undefined })).toThrow(
			/jwt\.audience is required when jwt\.validate is true/,
		);
	});

	it("rejects an empty audience array and an audience array containing an empty string", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, audience: [] })).toThrow(
			/jwt\.audience is required/,
		);
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, audience: [""] })).toThrow(
			/jwt\.audience is required/,
		);
	});

	// Drift case: the drifted createApp copy never looked at tokenType, so a
	// hand-built config could pin issuer and audience yet accept id_tokens.
	it("rejects a missing tokenType", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, tokenType: undefined })).toThrow(
			/jwt\.tokenType is required when jwt\.validate is true/,
		);
	});

	it("rejects an empty-string tokenType", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, tokenType: "" })).toThrow(
			/jwt\.tokenType is required/,
		);
	});

	// Drift case, found by the two-boundary parity table (#164): `tokenType` is
	// the accepted `typ` header, a single value the schema types `z.string()`,
	// where `issuer` and `audience` take lists because jose does. While all
	// three shared one list-tolerant check, this passed the guard, and jose then
	// threw a bare TypeError off the array on every request — a deployment that
	// booted and rejected every token, blaming its own infrastructure in the log.
	it.each([
		["a one-element array", ["at+jwt"]],
		["a multi-element array", ["at+jwt", "JWT"]],
		["an empty array", []],
	])(
		"rejects a tokenType that is %s, which jose cannot compare a typ header to",
		(_label, value) => {
			expect(() =>
				assertVerifyRouterJwtConfig({
					...VALID_VERIFYING,
					tokenType: value as unknown as string,
				}),
			).toThrow(/jwt\.tokenType is required/);
		},
	);
});

describe("assertVerifyRouterJwtConfig — decode-only configs (double opt-in, #106)", () => {
	it("accepts validate=false with the explicit acknowledgment", () => {
		expect(() =>
			assertVerifyRouterJwtConfig({ validate: false, allowInsecureDecode: true }),
		).not.toThrow();
	});

	it("rejects validate=false without the acknowledgment", () => {
		expect(() => assertVerifyRouterJwtConfig({ validate: false })).toThrow(/allowInsecureDecode/);
	});

	it("rejects validate=false with a merely-truthy acknowledgment — it must be `true`", () => {
		expect(() =>
			assertVerifyRouterJwtConfig({
				validate: false,
				allowInsecureDecode: "yes" as unknown as boolean,
			}),
		).toThrow(/allowInsecureDecode/);
	});
});

describe("assertVerifyRouterJwtConfig — caller-facing error context", () => {
	it("names the caller and the caller's config path so operators find the field they wrote", () => {
		// createApp's boundary speaks the wire config, where verifying mode is
		// selected by `oauth.jwt.mode = "verify"` — not by the internal `validate`
		// discriminant, which no longer exists as a wire key (#134). The caller
		// supplies its own phrasing of the gating condition.
		expect(() =>
			assertVerifyRouterJwtConfig(
				{ ...VALID_VERIFYING, issuer: [] },
				{ caller: "createApp", path: "oauth.jwt", verifyCondition: 'oauth.jwt.mode is "verify"' },
			),
		).toThrow(/^createApp: oauth\.jwt\.issuer is required when oauth\.jwt\.mode is "verify"/);
	});

	it("defaults to the authenticator's own boundary", () => {
		expect(() => assertVerifyRouterJwtConfig({ ...VALID_VERIFYING, tokenType: undefined })).toThrow(
			/^createTokenAuthenticator: jwt\.tokenType/,
		);
	});
});

describe("createTokenAuthenticator — construction and bearer parsing", () => {
	const silentLogger = { info() {}, warn() {}, error() {} };

	it.each([
		{ jkt: "proof-key" },
		{ "x5t#S256": "certificate" },
		{ jwk: { kty: "EC" } },
		{},
		null,
		"invalid",
	])("rejects a token with cnf %j on the Bearer-only boundary", async (cnf) => {
		const token = await signToken({ cnf });
		for (const config of [
			SIGNING_CONFIG,
			{ validate: false as const, allowInsecureDecode: true as const },
		]) {
			const authenticator = createTokenAuthenticator(config, silentLogger);
			expect(await authenticator.authenticate(`Bearer ${token}`)).toMatchObject({
				ok: false,
				code: "invalid_token",
			});
		}
	});

	it("runs the guard at construction, so a hand-built invalid config cannot produce an authenticator", () => {
		expect(() =>
			createTokenAuthenticator(
				{ ...VALID_VERIFYING, issuer: [""] } as unknown as VerifyRouterJwtConfig,
				silentLogger,
			),
		).toThrow(/jwt\.issuer is required/);
		expect(() =>
			createTokenAuthenticator(
				{ validate: false } as unknown as VerifyRouterJwtConfig,
				silentLogger,
			),
		).toThrow(/allowInsecureDecode/);
	});

	it("rejects an absent Authorization header as missing_token", async () => {
		const authenticator = createTokenAuthenticator(VALID_VERIFYING, silentLogger);
		const result = await authenticator.authenticate(undefined);
		expect(result).toMatchObject({ ok: false, code: "missing_token" });
	});

	it("rejects a non-Bearer scheme as unsupported_scheme", async () => {
		const authenticator = createTokenAuthenticator(VALID_VERIFYING, silentLogger);
		const result = await authenticator.authenticate("Basic dXNlcjpwdw==");
		expect(result).toMatchObject({ ok: false, code: "unsupported_scheme" });
	});

	it("rejects a Bearer header with no token as missing_token", async () => {
		const authenticator = createTokenAuthenticator(VALID_VERIFYING, silentLogger);
		const result = await authenticator.authenticate("Bearer ");
		expect(result).toMatchObject({ ok: false, code: "missing_token" });
	});

	// #158: the subject-bag field carrying the `Authorization` scheme used to
	// be called `tokenType`, which is also the config key for the accepted `typ`
	// header — two unrelated meanings under one name, one of them right beside
	// the other in this very module. The scheme is now `authScheme`, and this
	// pins the split so the collision cannot be reintroduced by either side.
	it("names the authorization scheme `authScheme`, distinct from the accepted `typ`", async () => {
		const authenticator = createTokenAuthenticator(SIGNING_CONFIG, silentLogger);
		const result = await authenticator.authenticate(`Bearer ${await signToken()}`);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.subject.authScheme).toBe("Bearer");
		// The accepted `typ` is config, not a fact about the presented token, so
		// nothing puts it on the subject bag under any name.
		expect(result.subject.tokenType).toBeUndefined();
	});

	// The other half of the rename, and the part a migrating consumer has to see:
	// the verifier used to write `tokenType` *after* spreading the claims, so a
	// token carrying a claim of that name had it silently overwritten by
	// `"Bearer"`. Nothing writes that slot now, so the claim reaches the subject
	// bag like any other custom claim. A consumer still reading `subject.tokenType`
	// is therefore reading the token, not the verifier — which is the opposite of
	// what it read before.
	it("no longer shadows a `tokenType` claim the token itself carries", async () => {
		const authenticator = createTokenAuthenticator(SIGNING_CONFIG, silentLogger);
		const token = await signToken({ tokenType: "from-the-token" });
		const result = await authenticator.authenticate(`Bearer ${token}`);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.subject.tokenType).toBe("from-the-token");
		// The scheme is unaffected: it has its own slot now, so a claim cannot
		// displace it and it cannot displace a claim.
		expect(result.subject.authScheme).toBe("Bearer");
	});

	// The time-claim bounds are resolved once at construction, so a config that
	// cannot state them never gets to serve a request with jose silently applying
	// its own semantics instead (#110).
	it("resolves the time-claim bounds at construction, so an unusable bound cannot serve", () => {
		expect(() =>
			createTokenAuthenticator(
				{ ...VALID_VERIFYING, maxTokenAgeSeconds: "forever" } as unknown as VerifyRouterJwtConfig,
				silentLogger,
			),
		).toThrow(/jwt\.maxTokenAgeSeconds must be a positive integer number of seconds/);
		expect(() =>
			createTokenAuthenticator(
				{
					validate: false,
					allowInsecureDecode: true,
					clockToleranceSeconds: -1,
				} as unknown as VerifyRouterJwtConfig,
				silentLogger,
			),
		).toThrow(/jwt\.clockToleranceSeconds must be an integer between 0 and 300 seconds/);
	});
});

/*
 * #110: the time-claim bounds and the decode-path checks that restate jose's
 * semantics for them. Two knobs, and both must reach both paths — a bound
 * threaded only into `jwtVerify` would leave decode-only mode accepting the
 * eternal token this issue is about.
 */

describe("resolveJwtTimeClaimBounds", () => {
	it("defaults both bounds when the config states neither", () => {
		expect(resolveJwtTimeClaimBounds({})).toEqual({ maxTokenAge: 86_400, clockTolerance: 0 });
	});

	it("coerces the strings a HOCON env substitution delivers", () => {
		expect(
			resolveJwtTimeClaimBounds({ maxTokenAgeSeconds: "600", clockToleranceSeconds: "60" }),
		).toEqual({ maxTokenAge: 600, clockTolerance: 60 });
	});

	it.each([0, -1, 1.5, "soon", true, null])(
		"rejects %o as a maxTokenAgeSeconds",
		(maxTokenAgeSeconds) => {
			expect(() =>
				resolveJwtTimeClaimBounds({ maxTokenAgeSeconds } as { maxTokenAgeSeconds?: number }),
			).toThrow(/jwt\.maxTokenAgeSeconds must be a positive integer number of seconds/);
		},
	);

	// Zero is the default and a deliberate choice: no skew allowance at all.
	it("accepts a zero clock tolerance", () => {
		expect(resolveJwtTimeClaimBounds({ clockToleranceSeconds: 0 }).clockTolerance).toBe(0);
	});

	// Bounded above on purpose (#110): tolerance extends the life of every token
	// the deployment accepts, so an unbounded knob is a way to spell "never expires".
	it.each([-1, 301, 86_400, 1.5])("rejects %o as a clockToleranceSeconds", (value) => {
		expect(() => resolveJwtTimeClaimBounds({ clockToleranceSeconds: value })).toThrow(
			/jwt\.clockToleranceSeconds must be an integer between 0 and 300 seconds/,
		);
	});

	it("accepts the ceiling itself", () => {
		expect(resolveJwtTimeClaimBounds({ clockToleranceSeconds: 300 }).clockTolerance).toBe(300);
	});

	it("names the caller's config path so operators find the key they wrote", () => {
		expect(() => resolveJwtTimeClaimBounds({ maxTokenAgeSeconds: 0 }, "oauth.jwt")).toThrow(
			/^oauth\.jwt\.maxTokenAgeSeconds must be/,
		);
	});
});

describe("assertTimeClaims — decode-path parity with jwtVerify", () => {
	const now = () => Math.floor(Date.now() / 1000);
	const BOUNDS: JwtTimeClaimBounds = { maxTokenAge: 86_400, clockTolerance: 0 };
	const fresh = (): JWTPayload => ({ iat: now(), exp: now() + 3600 });

	/** Runs the assertion and hands back whatever it threw, for claim/code checks. */
	function refusal(payload: JWTPayload, bounds: JwtTimeClaimBounds = BOUNDS): unknown {
		try {
			assertTimeClaims(payload, bounds);
		} catch (cause) {
			return cause;
		}
		throw new Error("expected assertTimeClaims to reject");
	}

	it("accepts a fresh token carrying iat and exp", () => {
		expect(() => assertTimeClaims(fresh(), BOUNDS)).not.toThrow();
	});

	// The whole of #110: jwtVerify checks exp only when present, which left a
	// token minted (or forged) without one valid forever.
	it("rejects a token carrying no exp claim", () => {
		const cause = refusal({ iat: now() });
		expect(cause).toBeInstanceOf(errors.JWTClaimValidationFailed);
		expect(cause).toMatchObject({ claim: "exp", reason: "missing" });
	});

	// maxTokenAge is measured from iat, so a token without one cannot be bounded.
	it("rejects a token carrying no iat claim", () => {
		const cause = refusal({ exp: now() + 3600 });
		expect(cause).toBeInstanceOf(errors.JWTClaimValidationFailed);
		expect(cause).toMatchObject({ claim: "iat", reason: "missing" });
	});

	it.each(["exp", "iat", "nbf"])("rejects a non-numeric %s claim", (claim) => {
		const cause = refusal({ ...fresh(), [claim]: "tomorrow" });
		expect(cause).toBeInstanceOf(errors.JWTClaimValidationFailed);
		expect(cause).toMatchObject({ claim, reason: "invalid" });
	});

	it("rejects an expired token with JWTExpired", () => {
		expect(refusal({ iat: now() - 7200, exp: now() - 3600 })).toBeInstanceOf(errors.JWTExpired);
	});

	it("rejects a not-yet-valid token", () => {
		const cause = refusal({ ...fresh(), nbf: now() + 3600 });
		expect(cause).toMatchObject({ claim: "nbf", reason: "check_failed" });
	});

	it("rejects a token issued longer ago than maxTokenAge, however far out its exp is", () => {
		const ancient = { iat: now() - 7200, exp: now() + 315_360_000 };
		expect(refusal(ancient, { maxTokenAge: 3600, clockTolerance: 0 })).toBeInstanceOf(
			errors.JWTExpired,
		);
		expect(() =>
			assertTimeClaims(ancient, { maxTokenAge: 86_400, clockTolerance: 0 }),
		).not.toThrow();
	});

	it("rejects a token issued in the future", () => {
		const cause = refusal({ iat: now() + 3600, exp: now() + 7200 });
		expect(cause).toBeInstanceOf(errors.JWTClaimValidationFailed);
		expect(cause).toMatchObject({ claim: "iat", reason: "check_failed" });
	});

	it("applies the clock tolerance to exp, nbf and maxTokenAge alike", () => {
		const tolerant: JwtTimeClaimBounds = { maxTokenAge: 60, clockTolerance: 60 };
		expect(() => assertTimeClaims({ iat: now() - 30, exp: now() - 30 }, tolerant)).not.toThrow();
		expect(() =>
			assertTimeClaims({ iat: now(), exp: now() + 3600, nbf: now() + 30 }, tolerant),
		).not.toThrow();
		expect(() => assertTimeClaims({ iat: now() - 90, exp: now() + 3600 }, tolerant)).not.toThrow();
	});
});
