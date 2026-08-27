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
import { describe, expect, it } from "vitest";
import {
	assertVerifyRouterJwtConfig,
	createTokenAuthenticator,
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
	const silentLogger = { warn() {}, error() {} };

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
});
