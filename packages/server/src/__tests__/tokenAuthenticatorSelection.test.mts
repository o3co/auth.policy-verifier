// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #219: which token authenticator a deployment runs is a config decision,
 * `oauth.authenticator`, read at both boundaries through one function — the
 * shape AGENTS.md "Two-Boundary Config Validation" asks for. The rows below
 * pin what that function decides and that `AppConfigSchema` reports the same
 * verdict at the same key, so a config file and a hand-built config cannot
 * disagree about whether `oauth.jwt` is required.
 */
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import {
	checkTokenAuthenticatorSelection,
	JWT_TOKEN_AUTHENTICATOR,
} from "#/config/tokenAuthenticatorSelection.mjs";

/** 64 hex characters — clears the #114 entropy floor, so no row fails on its secret. */
const SECRET = "11".repeat(32);

/** A complete verifying `oauth.jwt` block, so only the selection can decide a verdict. */
const JWT_BLOCK = {
	algorithm: "HS256",
	secret: SECRET,
	mode: "verify",
	issuer: "https://issuer.test",
	audience: "https://api.test",
};

const REST_OF_CONFIG = {
	attribute: { collectors: [] },
	rule: { collectors: [] },
};

describe("checkTokenAuthenticatorSelection (#219)", () => {
	it("names the built-in authenticator jwt", () => {
		expect(JWT_TOKEN_AUTHENTICATOR).toBe("jwt");
	});

	it("defaults an absent authenticator to jwt", () => {
		expect(checkTokenAuthenticatorSelection({ jwt: JWT_BLOCK })).toEqual({ ok: true, name: "jwt" });
	});

	it("takes any other name verbatim — the registry decides whether it exists", () => {
		expect(checkTokenAuthenticatorSelection({ authenticator: "introspection" })).toEqual({
			ok: true,
			name: "introspection",
		});
	});

	it("requires the jwt block when jwt is named", () => {
		expect(checkTokenAuthenticatorSelection({ authenticator: "jwt" })).toEqual({
			ok: false,
			key: "jwt",
			message: 'oauth.jwt is required when oauth.authenticator is "jwt"',
		});
	});

	it("requires the jwt block when jwt is the default, too", () => {
		expect(checkTokenAuthenticatorSelection({})).toEqual({
			ok: false,
			key: "jwt",
			message: 'oauth.jwt is required when oauth.authenticator is "jwt"',
		});
	});

	it("does not require the jwt block for another authenticator", () => {
		expect(checkTokenAuthenticatorSelection({ authenticator: "introspection" }).ok).toBe(true);
	});

	it("refuses a jwt block for another authenticator, naming that authenticator's own sub-block", () => {
		expect(
			checkTokenAuthenticatorSelection({ authenticator: "introspection", jwt: { mode: "verify" } }),
		).toEqual({
			ok: false,
			key: "jwt",
			message:
				'oauth.jwt is not read when oauth.authenticator is "introspection"; move its keys under oauth.introspection',
		});
	});

	it.each([
		["an empty string", ""],
		["a number", 42],
		["null", null],
		["a list", ["jwt"]],
	])("refuses %s as a name", (_label, authenticator) => {
		expect(checkTokenAuthenticatorSelection({ authenticator })).toEqual({
			ok: false,
			key: "authenticator",
			message: "oauth.authenticator must be a non-empty string",
		});
	});
});

describe("token authenticator selection — one reader at both boundaries (#219)", () => {
	interface Verdict {
		accepted: boolean;
		key: string | null;
	}

	function schemaVerdict(oauth: Record<string, unknown>): Verdict {
		const result = AppConfigSchema.safeParse({ oauth, ...REST_OF_CONFIG });
		if (result.success) return { accepted: true, key: null };
		const issue = result.error.issues.find((i) => i.path[0] === "oauth");
		return { accepted: false, key: issue ? String(issue.path[1]) : null };
	}

	function checkVerdict(oauth: Record<string, unknown>): Verdict {
		const check = checkTokenAuthenticatorSelection(oauth);
		return check.ok ? { accepted: true, key: null } : { accepted: false, key: check.key };
	}

	it.each([
		["jwt by default, with a jwt block", { jwt: JWT_BLOCK }],
		["jwt by name, with a jwt block", { authenticator: "jwt", jwt: JWT_BLOCK }],
		["jwt by default, with no jwt block", {}],
		["jwt by name, with no jwt block", { authenticator: "jwt" }],
		["another authenticator, with no jwt block", { authenticator: "introspection" }],
		[
			"another authenticator, keeping its own block",
			{
				authenticator: "introspection",
				introspection: { endpoint: "https://idp.test/introspect" },
			},
		],
		["an empty name", { authenticator: "", jwt: JWT_BLOCK }],
		// A jwt block under another authenticator is carried by nobody: refused
		// by both boundaries, naming the sub-block that authenticator reads.
		[
			"another authenticator, with a jwt block",
			{ authenticator: "introspection", jwt: { algorithm: "HS256", mode: "verify" } },
		],
	])("%s", (_label, oauth) => {
		expect(schemaVerdict(oauth)).toEqual(checkVerdict(oauth));
	});

	it("keeps another authenticator's own block on the parsed config, for its factory to read", () => {
		const parsed = AppConfigSchema.parse({
			oauth: {
				authenticator: "introspection",
				introspection: { endpoint: "https://idp.test/introspect" },
			},
			...REST_OF_CONFIG,
		});
		expect(parsed.oauth.authenticator).toBe("introspection");
		expect(parsed.oauth.jwt).toBeUndefined();
		expect((parsed.oauth as Record<string, unknown>).introspection).toEqual({
			endpoint: "https://idp.test/introspect",
		});
	});
});
