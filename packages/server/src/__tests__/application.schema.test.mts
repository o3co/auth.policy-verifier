// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
	AppConfigSchema,
	JWT_MODE_MIGRATION_MESSAGE,
	JWT_MODE_REMOVED_KEYS,
} from "#/config/application.schema.mjs";
import { MAX_PREVIOUS_SECRETS, MIN_SECRET_ENTROPY_BYTES } from "#/config/defaults.mjs";
import { checkHs256Rotation, parseHs256Rotation } from "#/jwt/hs256Rotation.mjs";
import { type JwksFetchConfig, resolveJwksFetchBounds } from "#/jwt/jwks.mjs";
import { type JwtTimeClaimConfig, resolveJwtTimeClaimBounds } from "#/jwt/tokenAuthenticator.mjs";

const baseBody = {
	attribute: { collectors: [] },
	rule: { collectors: [] },
};

/**
 * 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces on
 * every HS256 secret. Every HS256 fixture in this file has to clear it, so the
 * cases about other keys are not silently testing a rejected secret instead.
 */
const SECRET = "11".repeat(32);
const OLD_SECRET = "22".repeat(32);

/** Issuer/audience are required whenever validation is on; most cases here only care about keys. */
const rfc9068 = { issuer: "https://issuer.test", audience: "https://api.test" };

describe("AppConfigSchema — JWT algorithm validation", () => {
	it("rejects HS256 without secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "verify", ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message === "secret is required for HS256")).toBe(
				true,
			);
		}
	});

	it.each(["RS256", "ES256", "EdDSA"])("rejects %s without any key source", (algorithm) => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm, mode: "verify", ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(
				result.error.issues.some((i) =>
					i.message.includes(`jwksUri or publicKey/publicKeyPath is required for ${algorithm}`),
				),
			).toBe(true);
		}
	});

	it("accepts unknown algorithm names (validated at registry lookup, not at schema)", () => {
		// User-registered algorithms are responsible for their own config validation
		// inside their KeyResolverFactory. The schema intentionally accepts any string.
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "ES384", mode: "verify", custom: "value", ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("accepts HS256 with secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("skips key-material validation in insecure-decode mode", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "RS256", mode: "insecure-decode" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema — HS256 secret entropy floor (#114)", () => {
	const FUTURE = "2999-01-01T00:00:00Z";

	/** Parses an `oauth.jwt` HS256 block with the RFC 9068 fields in place. */
	const parseJwt = (jwt: Record<string, unknown>) =>
		AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "verify", ...rfc9068, ...jwt } },
			...baseBody,
		});

	it.each([
		["a one-character secret", "x"],
		["the README's old example value", "your-secret"],
		["a 32-character hex secret — 16 decoded bytes", "ab".repeat(16)],
		["32 alphanumerics — a base64 body carrying 24 bytes", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"],
	])("refuses %s at config-parse time", (_label, secret) => {
		const result = parseJwt({ secret });
		expect(result.success).toBe(false);
		if (!result.success) {
			const issue = result.error.issues.find((i) => i.path.at(-1) === "secret");
			expect(issue?.message).toMatch(/at least 32 bytes/);
			expect(issue?.message).toMatch(/openssl rand -hex 32/);
		}
	});

	it("never echoes the rejected secret into the failure", () => {
		const result = parseJwt({ secret: "hunter2-do-not-leak" });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(JSON.stringify(result.error.issues)).not.toContain("hunter2-do-not-leak");
		}
	});

	it.each([
		["a 64-character hex secret", SECRET],
		["a padded base64 secret", "qmV+afsq/SMZ7hPGs9edVQDvPzNmjXemJNjqti181v0="],
		["a passphrase at exactly the floor", `${"a".repeat(MIN_SECRET_ENTROPY_BYTES - 1)}!`],
	])("accepts %s", (_label, secret) => {
		expect(parseJwt({ secret }).success).toBe(true);
	});

	it("holds every previousSecrets entry to the same floor (#112 rotation)", () => {
		const result = parseJwt({
			secret: SECRET,
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: "x", expiresAt: FUTURE }],
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const issue = result.error.issues.find((i) => i.message.includes("previousSecrets[0]"));
			expect(issue?.path).toEqual(["oauth", "jwt", "previousSecrets", 0, "secret"]);
			expect(issue?.message).toMatch(/at least 32 bytes/);
		}
	});

	it("does not apply the floor in insecure-decode mode — no key material is used", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "insecure-decode", secret: "x" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema — JWKS transport security (#109)", () => {
	const httpsUri = "https://auth-provider.test/.well-known/jwks.json";
	const rs256 = { algorithm: "RS256", mode: "verify", jwksUri: httpsUri, ...rfc9068 };

	/** Parses an RS256 verify config whose JWKS keys the case under test overrides. */
	const parseWithJwks = (jwt: Record<string, unknown>) =>
		AppConfigSchema.safeParse({ oauth: { jwt: { ...rs256, ...jwt } }, ...baseBody });

	it("accepts an https jwksUri", () => {
		expect(parseWithJwks({}).success).toBe(true);
	});

	it("rejects a plaintext jwksUri at config-parse time, not at first request", () => {
		const result = parseWithJwks({ jwksUri: "http://auth-provider:3000/.well-known/jwks.json" });
		expect(result.success).toBe(false);
		if (!result.success) {
			const issue = result.error.issues.find((i) => i.path.at(-1) === "jwksUri");
			expect(issue?.message).toContain("https");
		}
	});

	it.each([
		"http://localhost:3000/.well-known/jwks.json",
		"http://127.0.0.1:3000/.well-known/jwks.json",
		"http://[::1]:3000/.well-known/jwks.json",
	])("accepts plaintext %s — the loopback carve-out", (jwksUri) => {
		expect(parseWithJwks({ jwksUri }).success).toBe(true);
	});

	it("rejects a jwksUri that is not an absolute URL", () => {
		expect(parseWithJwks({ jwksUri: "auth-provider/.well-known/jwks.json" }).success).toBe(false);
	});

	it("leaves the jwksUri unchecked in insecure-decode mode — no key is ever fetched", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					algorithm: "RS256",
					mode: "insecure-decode",
					jwksUri: "http://auth-provider:3000/.well-known/jwks.json",
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("defaults the JWKS fetch bounds", () => {
		const result = AppConfigSchema.parse({ oauth: { jwt: rs256 }, ...baseBody });
		expect(result.oauth.jwt.jwksTimeoutMs).toBe(5000);
		expect(result.oauth.jwt.jwksCooldownMs).toBe(30_000);
		expect(result.oauth.jwt.jwksCacheMaxAgeMs).toBe(600_000);
	});

	it("coerces the strings a HOCON env substitution produces", () => {
		const result = AppConfigSchema.parse({
			oauth: {
				jwt: {
					...rs256,
					jwksTimeoutMs: "2000",
					jwksCooldownMs: "10000",
					jwksCacheMaxAgeMs: "120000",
				},
			},
			...baseBody,
		});
		expect(result.oauth.jwt.jwksTimeoutMs).toBe(2000);
		expect(result.oauth.jwt.jwksCooldownMs).toBe(10_000);
		expect(result.oauth.jwt.jwksCacheMaxAgeMs).toBe(120_000);
	});

	it.each(["jwksTimeoutMs", "jwksCacheMaxAgeMs"])("rejects a non-positive %s", (key) => {
		for (const value of [0, -1, 1.5]) {
			const result = parseWithJwks({ [key]: value });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues.some((i) => i.path.at(-1) === key)).toBe(true);
			}
		}
	});

	it("rejects a negative cooldown", () => {
		expect(parseWithJwks({ jwksCooldownMs: -1 }).success).toBe(false);
	});

	it("accepts a zero cooldown — refetching on every miss is a deliberate choice", () => {
		expect(parseWithJwks({ jwksCooldownMs: 0 }).success).toBe(true);
	});
});

describe("AppConfigSchema — empty rule set policy", () => {
	it("defaults rule.onEmptyRuleSet to deny", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 } },
			...baseBody,
		});
		expect(result.rule.onEmptyRuleSet).toBe("deny");
	});

	it("accepts an explicit allow opt-out", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 } },
			attribute: { collectors: [] },
			rule: { collectors: [], onEmptyRuleSet: "allow" },
		});
		expect(result.rule.onEmptyRuleSet).toBe("allow");
	});

	it("rejects an unrecognized onEmptyRuleSet value", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 } },
			attribute: { collectors: [] },
			rule: { collectors: [], onEmptyRuleSet: "maybe" },
		});
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — RFC 9068 token validation (#105)", () => {
	const hs256 = { algorithm: "HS256", secret: SECRET };

	it('rejects mode="verify" without an issuer', () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, mode: "verify", audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message.includes("issuer"))).toBe(true);
		}
	});

	it('rejects mode="verify" without an audience', () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, mode: "verify", issuer: "https://issuer.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message.includes("audience"))).toBe(true);
		}
	});

	it("rejects an empty issuer string", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, mode: "verify", issuer: "", audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it("accepts an audience list", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					mode: "verify",
					issuer: "https://issuer.test",
					audience: ["https://api.test", "https://api2.test"],
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("defaults tokenType to at+jwt", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { ...hs256, mode: "verify", ...rfc9068 } },
			...baseBody,
		});
		expect(result.oauth.jwt.tokenType).toBe("at+jwt");
	});

	it("does not require issuer/audience in insecure-decode mode", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "insecure-decode" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema — batch decisions (#124)", () => {
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	it("defaults verify.maxBatchSize to 50", () => {
		const result = AppConfigSchema.parse({ oauth: { jwt: validJwt }, ...baseBody });
		expect(result.verify.maxBatchSize).toBe(50);
	});

	it("accepts an operator-set cap", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			verify: { maxBatchSize: 200 },
		});
		expect(result.verify.maxBatchSize).toBe(200);
	});

	it("coerces the string a HOCON env substitution produces", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			verify: { maxBatchSize: "25" },
		});
		expect(result.verify.maxBatchSize).toBe(25);
	});

	it.each([0, -1, 1.5])("rejects %s as a cap", (value) => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: validJwt },
			...baseBody,
			verify: { maxBatchSize: value },
		});
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — token lifetime bounds (#110)", () => {
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	/** Parses a valid verify config whose lifetime bounds the case under test overrides. */
	const parseWithBounds = (jwt: Record<string, unknown>) =>
		AppConfigSchema.safeParse({ oauth: { jwt: { ...validJwt, ...jwt } }, ...baseBody });

	it("defaults maxTokenAgeSeconds to a day and clockToleranceSeconds to zero", () => {
		const result = AppConfigSchema.parse({ oauth: { jwt: validJwt }, ...baseBody });
		expect(result.oauth.jwt.maxTokenAgeSeconds).toBe(86_400);
		expect(result.oauth.jwt.clockToleranceSeconds).toBe(0);
	});

	// The defaults must reach insecure-decode deployments too: the decode path
	// restates these checks by hand, and a mode that skipped them would accept
	// the eternal token the verifying mode refuses.
	it("defaults both bounds in insecure-decode mode as well", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { mode: "insecure-decode" } },
			...baseBody,
		});
		expect(result.oauth.jwt.maxTokenAgeSeconds).toBe(86_400);
		expect(result.oauth.jwt.clockToleranceSeconds).toBe(0);
	});

	it("coerces the strings a HOCON env substitution produces", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { ...validJwt, maxTokenAgeSeconds: "600", clockToleranceSeconds: "60" } },
			...baseBody,
		});
		expect(result.oauth.jwt.maxTokenAgeSeconds).toBe(600);
		expect(result.oauth.jwt.clockToleranceSeconds).toBe(60);
	});

	it.each([0, -1, 1.5])("rejects %s as a maxTokenAgeSeconds", (value) => {
		const result = parseWithBounds({ maxTokenAgeSeconds: value });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.at(-1) === "maxTokenAgeSeconds")).toBe(true);
		}
	});

	it("accepts a zero clock tolerance — no skew allowance is the default and a valid choice", () => {
		expect(parseWithBounds({ clockToleranceSeconds: 0 }).success).toBe(true);
	});

	// Bounded above on purpose: tolerance extends the life of every token the
	// deployment accepts, so an unbounded knob is a way to spell "never expires".
	it.each([-1, 301, 86_400, 1.5])("rejects %s as a clockToleranceSeconds", (value) => {
		const result = parseWithBounds({ clockToleranceSeconds: value });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.at(-1) === "clockToleranceSeconds")).toBe(true);
		}
	});

	it("accepts the clock-tolerance ceiling itself", () => {
		expect(parseWithBounds({ clockToleranceSeconds: 300 }).success).toBe(true);
	});
});

describe("AppConfigSchema — one numeric reader at both boundaries (#157)", () => {
	// The doctrine `checkJwksUri` and `checkHs256Rotation` follow: an invariant is
	// stated once and spent twice, so a hand-built config cannot get a different
	// answer from a parsed one. The numeric knobs were the exception — the schema
	// re-implemented each as a `z.coerce.number()` chain and shared only the
	// constants with `resolveBound`, which is how the two rows below came to
	// disagree. Every case here asserts the two boundaries character for
	// character, because a message that drifts is a check that has drifted.
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	/** Parses a valid verify config whose `oauth.jwt` knobs the case under test overrides. */
	const parseJwt = (jwt: Record<string, unknown>) =>
		AppConfigSchema.safeParse({ oauth: { jwt: { ...validJwt, ...jwt } }, ...baseBody });

	/** The schema's message for one key, or `undefined` when it accepted the value. */
	function schemaRefusal(config: Record<string, unknown>, key: string): string | undefined {
		const result = parseJwt(config);
		if (result.success) {
			return undefined;
		}
		return result.error.issues.find((issue) => issue.path.at(-1) === key)?.message;
	}

	/** The runtime guard's message for the same value, or `undefined` when it accepted it. */
	function guardRefusal(resolve: () => unknown): string | undefined {
		try {
			resolve();
			return undefined;
		} catch (cause) {
			return (cause as Error).message;
		}
	}

	/**
	 * Every `oauth.jwt` numeric knob, paired with the resolver that reads it for a
	 * config `createApp` was handed rather than one it parsed. The casts are the
	 * point: a hand-built config's static types cannot be trusted, which is why
	 * the guard exists at all.
	 */
	const jwtKnobs = [
		{
			key: "jwksTimeoutMs",
			resolve: (value: unknown) =>
				resolveJwksFetchBounds({ jwksTimeoutMs: value } as JwksFetchConfig, "oauth.jwt"),
		},
		{
			key: "jwksCooldownMs",
			resolve: (value: unknown) =>
				resolveJwksFetchBounds({ jwksCooldownMs: value } as JwksFetchConfig, "oauth.jwt"),
		},
		{
			key: "jwksCacheMaxAgeMs",
			resolve: (value: unknown) =>
				resolveJwksFetchBounds({ jwksCacheMaxAgeMs: value } as JwksFetchConfig, "oauth.jwt"),
		},
		{
			key: "maxTokenAgeSeconds",
			resolve: (value: unknown) =>
				resolveJwtTimeClaimBounds({ maxTokenAgeSeconds: value } as JwtTimeClaimConfig, "oauth.jwt"),
		},
		{
			key: "clockToleranceSeconds",
			resolve: (value: unknown) =>
				resolveJwtTimeClaimBounds(
					{ clockToleranceSeconds: value } as JwtTimeClaimConfig,
					"oauth.jwt",
				),
		},
	] as const;

	/**
	 * Values no numeric knob may take, whatever its floor. `false` and `""` are
	 * here rather than in a per-knob list on purpose: `Number(false)` and
	 * `Number("")` are both 0, which the knobs whose floor is 0 would otherwise
	 * accept as a deliberate zero.
	 */
	const refusedEverywhere: [string, unknown][] = [
		["true", true],
		["false", false],
		["null", null],
		["an empty string", ""],
		["a non-numeric string", "abc"],
		["a fractional value", 1.5],
		["an array", []],
		["an object", {}],
	];

	for (const knob of jwtKnobs) {
		describe(knob.key, () => {
			it.each(refusedEverywhere)(
				"refuses %s at both boundaries, in one wording",
				(_label, value) => {
					const fromGuard = guardRefusal(() => knob.resolve(value));
					expect(fromGuard).toBeDefined();
					expect(schemaRefusal({ [knob.key]: value }, knob.key)).toBe(fromGuard);
				},
			);
		});
	}

	// The two rows of #157's table, named so the regression is recognisable: the
	// schema read `false` as a zero cooldown and `true` as a one-millisecond
	// timeout, each of which the runtime guard refused to boot on.
	it("refuses jwksCooldownMs = false, which used to parse to 0", () => {
		expect(schemaRefusal({ jwksCooldownMs: false }, "jwksCooldownMs")).toBe(
			"oauth.jwt.jwksCooldownMs must be a non-negative integer number of milliseconds, got false",
		);
	});

	it("refuses jwksTimeoutMs = true, which used to become a 1 ms timeout", () => {
		expect(schemaRefusal({ jwksTimeoutMs: true }, "jwksTimeoutMs")).toBe(
			"oauth.jwt.jwksTimeoutMs must be a positive integer number of milliseconds, got true",
		);
	});

	it("still takes the strings a HOCON env substitution delivers, for every knob", () => {
		// The whole point of routing through `resolveBound` is that it coerces the
		// string form itself. A knob that stopped accepting "2000" would break
		// every deployment configured through the environment.
		const result = parseJwt({
			jwksTimeoutMs: "2000",
			jwksCooldownMs: "0",
			jwksCacheMaxAgeMs: "120000",
			maxTokenAgeSeconds: "600",
			clockToleranceSeconds: "60",
		});
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.oauth.jwt).toMatchObject({
				jwksTimeoutMs: 2000,
				jwksCooldownMs: 0,
				jwksCacheMaxAgeMs: 120_000,
				maxTokenAgeSeconds: 600,
				clockToleranceSeconds: 60,
			});
		}
	});

	it("reports two bad knobs in one block, not just the first", () => {
		// The reason the wrapper's issue is non-fatal. A fatal one would abort the
		// block at the first refusal and make a two-mistake config a two-round-trip
		// fix, which is the property `checkHs256Rotation` is built around.
		const result = parseJwt({ jwksTimeoutMs: false, clockToleranceSeconds: 999 });
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.map((issue) => issue.path.at(-1)).sort()).toEqual([
				"clockToleranceSeconds",
				"jwksTimeoutMs",
			]);
		}
	});

	it("leaves a sibling block's superRefine running when a knob elsewhere is refused", () => {
		// zod skips a block's `superRefine` once a field *in that block* failed, so
		// a refused `oauth.jwt` knob hides the RFC 9068 checks beside it. A refused
		// `http.port` does not: different block, so the jwt checks still report.
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "verify", audience: "https://api.test" } },
			...baseBody,
			http: { port: false },
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			const messages = result.error.issues.map((issue) => issue.message);
			expect(messages).toContain("http.port must be an integer between 1 and 65535, got false");
			expect(messages).toContain('issuer is required when mode is "verify" (RFC 9068 §4)');
			expect(messages).toContain("secret is required for HS256");
		}
	});

	it("keeps the defaults reachable through the same reader", () => {
		const result = parseJwt({});
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.oauth.jwt).toMatchObject({
				jwksTimeoutMs: 5_000,
				jwksCooldownMs: 30_000,
				jwksCacheMaxAgeMs: 600_000,
				maxTokenAgeSeconds: 86_400,
				clockToleranceSeconds: 0,
			});
		}
	});
});

describe("AppConfigSchema — http.port (#157)", () => {
	// The one numeric knob that predates the campaign and was never bounded
	// (noted in #158): `z.coerce.number()` with no `.int().positive()` at all.
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	const parsePort = (port: unknown) =>
		AppConfigSchema.safeParse({ oauth: { jwt: validJwt }, ...baseBody, http: { port } });

	it("defaults to 3000 when the http section is absent", () => {
		const result = AppConfigSchema.parse({ oauth: { jwt: validJwt }, ...baseBody });
		expect(result.http.port).toBe(3000);
	});

	it("defaults to 3000 when the http section omits it", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { hostname: "0.0.0.0" },
		});
		expect(result.http.port).toBe(3000);
	});

	it("takes the string HTTP_PORT delivers", () => {
		const result = parsePort("8080");
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.http.port).toBe(8080);
		}
	});

	it.each([
		// 0 is a real hazard, not a formality: listen(0) binds an arbitrary free
		// port, so the enforcement layer's configured address stops resolving to
		// this process — and 0 is what `Number(false)` and `Number(null)` produced.
		["zero", 0],
		["a negative port", -1],
		["a port above the 16-bit range", 65_536],
		["a fractional port", 3.5],
		["a non-numeric string", "abc"],
		["an empty string", ""],
		["true", true],
		["false", false],
		["null", null],
	])("refuses %s", (_label, port) => {
		const result = parsePort(port);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((issue) => issue.path.join(".") === "http.port")).toBe(true);
		}
	});

	it("accepts the last usable port", () => {
		expect(parsePort(65_535).success).toBe(true);
	});

	it("names the key the operator wrote, in the shape every other knob uses", () => {
		const result = parsePort("abc");
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.find((issue) => issue.path.at(-1) === "port")?.message).toBe(
				'http.port must be an integer between 1 and 65535, got "abc"',
			);
		}
	});
});

describe("AppConfigSchema — multiple acceptable issuers (#105)", () => {
	const hs256 = { algorithm: "HS256", secret: SECRET };

	it("accepts an issuer list, matching the router's issuer type", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					mode: "verify",
					issuer: ["https://issuer.test", "https://issuer-2.test"],
					audience: "https://api.test",
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("rejects an empty issuer list", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, mode: "verify", issuer: [], audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it("rejects an issuer list carrying an empty entry", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					mode: "verify",
					issuer: ["https://issuer.test", ""],
					audience: "https://api.test",
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — logging (#107)", () => {
	const validBody = {
		oauth: { jwt: { mode: "insecure-decode" } },
		...baseBody,
	};

	it("defaults logging.level to info when the section is absent", () => {
		// The E2E overlay config is mounted OVER the template's application.conf,
		// so a key it does not repeat is simply absent — the section must default.
		const result = AppConfigSchema.parse(validBody);
		expect(result.logging).toEqual({ level: "info" });
	});

	it.each(["trace", "debug", "info", "warn", "error", "fatal", "silent"] as const)(
		"accepts logging.level=%s",
		(level) => {
			const result = AppConfigSchema.parse({ ...validBody, logging: { level } });
			expect(result.logging.level).toBe(level);
		},
	);

	it("rejects an unknown logging.level", () => {
		const result = AppConfigSchema.safeParse({ ...validBody, logging: { level: "verbose" } });
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — oauth.jwt.mode (#134)", () => {
	// Assert against the exported constant, not a copy of the string: the
	// operator-facing migration text is the contract, and a test that restates
	// it can drift from what the schema actually emits.
	const migration = JWT_MODE_MIGRATION_MESSAGE;

	it('defaults mode to "verify"', () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { secret: SECRET, ...rfc9068 } },
			...baseBody,
		});
		expect(result.oauth.jwt.mode).toBe("verify");
	});

	it("enforces the verify-mode requirements when mode is omitted", () => {
		// The default must not be a way to skip iss/aud: an omitted mode is
		// verify mode, so a config with no issuer still fails to parse.
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { secret: SECRET } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it('accepts mode="insecure-decode" with no key material — the string itself is the consent', () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { mode: "insecure-decode" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("rejects an unknown mode value", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { mode: "decode", secret: SECRET, ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it("rejects a boolean mode — an accidental env-var flip cannot select insecure-decode", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { mode: false, secret: SECRET, ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	// Driven off the exported list, not a copy of it (#158): the removed keys are
	// half of the same contract the migration message is, and a fourth key added
	// to the constant must be covered here without anyone remembering to widen a
	// literal in a test.
	it.each([...JWT_MODE_REMOVED_KEYS])(
		"hard-errors on the removed key %s with the migration message",
		(staleKey) => {
			const result = AppConfigSchema.safeParse({
				oauth: { jwt: { secret: SECRET, ...rfc9068, [staleKey]: true } },
				...baseBody,
			});
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(result.error.issues.some((i) => i.message === migration)).toBe(true);
			}
		},
	);

	it("rejects the old decode-only pair as stale keys, not as a valid decode config", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { validate: false, allowInsecureDecode: true } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message === migration)).toBe(true);
		}
	});
});

describe("AppConfigSchema — http bind address (#108)", () => {
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	it("defaults http.hostname to loopback when the http section is absent", () => {
		// A verifier is a sidecar by default: reachable only from the process
		// that enforces its decisions, not from every pod on the network.
		const result = AppConfigSchema.parse({ oauth: { jwt: validJwt }, ...baseBody });
		expect(result.http.hostname).toBe("127.0.0.1");
	});

	it("defaults http.hostname to loopback when the http section omits it", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { port: 8080 },
		});
		expect(result.http.hostname).toBe("127.0.0.1");
	});

	it("accepts an explicit all-interfaces bind", () => {
		// Container deployments need it; it is now an opt-in rather than the default.
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { hostname: "0.0.0.0" },
		});
		expect(result.http.hostname).toBe("0.0.0.0");
	});
});

describe("AppConfigSchema — http.callerAuth (#108)", () => {
	const validJwt = { algorithm: "HS256", secret: SECRET, mode: "verify", ...rfc9068 };

	it("leaves http.callerAuth absent when nothing configures it", () => {
		const result = AppConfigSchema.parse({ oauth: { jwt: validJwt }, ...baseBody });
		expect(result.http.callerAuth).toBeUndefined();
	});

	it("defaults the header name when only a token is configured", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { callerAuth: { token: "s3cret" } },
		});
		expect(result.http.callerAuth).toEqual({ header: "x-caller-token", token: "s3cret" });
	});

	it("accepts an operator-chosen header name", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { callerAuth: { header: "x-api-key", token: "s3cret" } },
		});
		expect(result.http.callerAuth?.header).toBe("x-api-key");
	});

	it("keeps the block usable when the token substitution resolved to nothing", () => {
		// HOCON `token = ${?HTTP_CALLER_AUTH_TOKEN}` leaves the key absent when the
		// variable is unset, while the surrounding block still exists because of
		// the header default. That must mean "not configured", not "malformed".
		const result = AppConfigSchema.parse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { callerAuth: { header: "x-caller-token" } },
		});
		expect(result.http.callerAuth?.token).toBeUndefined();
	});

	it("rejects an empty token rather than treating it as disabled", () => {
		// `HTTP_CALLER_AUTH_TOKEN=` substitutes an empty string. Booting
		// unauthenticated because a credential was exported empty is exactly the
		// silent failure this issue is about.
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { callerAuth: { token: "" } },
		});
		expect(result.success).toBe(false);
	});

	it("rejects an empty header name", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: validJwt },
			...baseBody,
			http: { callerAuth: { header: "", token: "s3cret" } },
		});
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — HS256 secret rotation (#112)", () => {
	const FUTURE = "2999-01-01T00:00:00Z";

	/** Parses an `oauth.jwt` block with the RFC 9068 fields already in place. */
	function parseJwt(jwt: Record<string, unknown>) {
		return AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "verify", ...rfc9068, ...jwt } },
			...baseBody,
		});
	}

	it("accepts a rotation block and keeps it on the parsed config", () => {
		const previousSecrets = [{ kid: "v0", secret: OLD_SECRET, expiresAt: FUTURE }];
		const result = parseJwt({ secret: SECRET, kid: "v1", previousSecrets });
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.oauth.jwt.previousSecrets).toEqual(previousSecrets);
			expect(result.data.oauth.jwt.kid).toBe("v1");
		}
	});

	it("accepts a single-secret config unchanged", () => {
		const result = parseJwt({ secret: SECRET });
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.oauth.jwt.previousSecrets).toBeUndefined();
		}
	});

	it("accepts an explicit empty list as 'nothing is being rotated'", () => {
		const result = parseJwt({ secret: SECRET, previousSecrets: [] });
		expect(result.success).toBe(true);
	});

	describe("null is not a spelling for omitted", () => {
		// The two boundaries must agree: `AppConfigSchema` serves config files and
		// `checkHs256Rotation` serves hand-built configs that never met it, and a
		// value one accepts while the other refuses is the divergence the runtime
		// guard exists to prevent.
		it("is refused by the schema, at the field the operator wrote", () => {
			const result = parseJwt({ secret: SECRET, previousSecrets: null });
			expect(result.success).toBe(false);
			if (!result.success) {
				expect(
					result.error.issues.some((i) => i.path.join(".") === "oauth.jwt.previousSecrets"),
				).toBe(true);
			}
		});

		it("is refused by the runtime guard the same way", () => {
			const checked = checkHs256Rotation({ secret: SECRET, previousSecrets: null });
			expect(checked.ok).toBe(false);
			expect(() => parseHs256Rotation({ secret: SECRET, previousSecrets: null })).toThrow(
				/^oauth\.jwt\.previousSecrets must be an array/,
			);
		});

		it("leaves the two boundaries agreeing on every spelling of 'nothing'", () => {
			// undefined and [] pass both; null passes neither.
			for (const previousSecrets of [undefined, []]) {
				expect(parseJwt({ secret: SECRET, previousSecrets }).success).toBe(true);
				expect(checkHs256Rotation({ secret: SECRET, previousSecrets }).ok).toBe(true);
			}
			expect(parseJwt({ secret: SECRET, previousSecrets: null }).success).toBe(false);
			expect(checkHs256Rotation({ secret: SECRET, previousSecrets: null }).ok).toBe(false);
		});
	});

	it("requires a kid once a previous secret is configured", () => {
		const result = parseJwt({
			secret: SECRET,
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: FUTURE }],
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.join(".") === "oauth.jwt.kid")).toBe(true);
		}
	});

	it("caps previousSecrets, reporting at the field the operator wrote", () => {
		const result = parseJwt({
			secret: SECRET,
			kid: "current",
			previousSecrets: Array.from({ length: MAX_PREVIOUS_SECRETS + 1 }, (_, i) => ({
				kid: `v${i}`,
				secret: OLD_SECRET,
				expiresAt: FUTURE,
			})),
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(
				result.error.issues.some((i) => i.path.join(".") === "oauth.jwt.previousSecrets"),
			).toBe(true);
		}
	});

	it("reports a malformed entry at its own index", () => {
		const result = parseJwt({
			secret: SECRET,
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: "soon" }],
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(
				result.error.issues.some(
					(i) => i.path.join(".") === "oauth.jwt.previousSecrets.0.expiresAt",
				),
			).toBe(true);
		}
	});

	/** Parses an asymmetric block carrying whatever `previousSecrets` is given. */
	function parseAsymmetric(previousSecrets: unknown) {
		return AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					algorithm: "EdDSA",
					mode: "verify",
					...rfc9068,
					publicKey: "-----BEGIN PUBLIC KEY-----",
					previousSecrets,
				},
			},
			...baseBody,
		});
	}

	it.each([
		["a populated list", [{ kid: "v0", secret: OLD_SECRET, expiresAt: FUTURE }]],
		// The empty list is the case a config snippet is most likely to carry, and
		// it is refused too: the guard is on the key being present, not on it
		// having entries. Any doc example must therefore keep this key out of a
		// block an operator could copy for an asymmetric algorithm.
		["an empty list", []],
	])("refuses previousSecrets under an asymmetric algorithm — %s", (_label, previousSecrets) => {
		// Mirrors auth.provider's guard: the asymmetric algorithms rotate through
		// the JWKS, so a leftover HS256 rotation block would be silently dropped.
		const result = parseAsymmetric(previousSecrets);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message.includes("previousSecrets"))).toBe(true);
		}
	});

	it("accepts an asymmetric config that simply omits previousSecrets", () => {
		expect(parseAsymmetric(undefined).success).toBe(true);
	});

	it("accepts kid under an asymmetric algorithm — ignored, never a boot failure", () => {
		// `kid` is HS256-only in effect, but jose matches it against the fetched
		// JWKS, so leaving it on an asymmetric config must not refuse the boot.
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					algorithm: "EdDSA",
					mode: "verify",
					...rfc9068,
					publicKey: "-----BEGIN PUBLIC KEY-----",
					kid: "v1",
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("leaves the rotation block alone in insecure-decode mode", () => {
		// Nothing verifies a signature there, so no key material is checked at all.
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", mode: "insecure-decode" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});
