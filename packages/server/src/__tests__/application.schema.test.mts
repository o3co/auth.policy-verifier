// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

const baseBody = {
	attribute: { collectors: [] },
	rule: { collectors: [] },
};

/** Issuer/audience are required whenever validation is on; most cases here only care about keys. */
const rfc9068 = { issuer: "https://issuer.test", audience: "https://api.test" };

describe("AppConfigSchema — JWT algorithm validation", () => {
	it("rejects HS256 without secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", validate: true, ...rfc9068 } },
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
			oauth: { jwt: { algorithm, validate: true, ...rfc9068 } },
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
			oauth: { jwt: { algorithm: "ES384", validate: true, custom: "value", ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("accepts HS256 with secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", secret: "s", validate: true, ...rfc9068 } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("skips validation when validate=false (no key material required)", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "RS256", validate: false } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema — RFC 9068 token validation (#105)", () => {
	const hs256 = { algorithm: "HS256", secret: "s" };

	it("rejects validate=true without an issuer", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, validate: true, audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message.includes("issuer"))).toBe(true);
		}
	});

	it("rejects validate=true without an audience", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, validate: true, issuer: "https://issuer.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.message.includes("audience"))).toBe(true);
		}
	});

	it("rejects an empty issuer string", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { ...hs256, validate: true, issuer: "", audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it("accepts an audience list", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					validate: true,
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
			oauth: { jwt: { ...hs256, validate: true, ...rfc9068 } },
			...baseBody,
		});
		expect(result.oauth.jwt.tokenType).toBe("at+jwt");
	});

	it("does not require issuer/audience when validation is disabled", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", validate: false } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});
});

describe("AppConfigSchema — multiple acceptable issuers (#105)", () => {
	const hs256 = { algorithm: "HS256", secret: "s" };

	it("accepts an issuer list, matching the router's issuer type", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					validate: true,
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
			oauth: { jwt: { ...hs256, validate: true, issuer: [], audience: "https://api.test" } },
			...baseBody,
		});
		expect(result.success).toBe(false);
	});

	it("rejects an issuer list carrying an empty entry", () => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					...hs256,
					validate: true,
					issuer: ["https://issuer.test", ""],
					audience: "https://api.test",
				},
			},
			...baseBody,
		});
		expect(result.success).toBe(false);
	});
});

describe("AppConfigSchema — empty rule set policy", () => {
	it("defaults rule.onEmptyRuleSet to deny", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { algorithm: "HS256", secret: "s", validate: true, ...rfc9068 } },
			...baseBody,
		});
		expect(result.rule.onEmptyRuleSet).toBe("deny");
	});

	it("accepts an explicit allow opt-out", () => {
		const result = AppConfigSchema.parse({
			oauth: { jwt: { algorithm: "HS256", secret: "s", validate: true, ...rfc9068 } },
			attribute: { collectors: [] },
			rule: { collectors: [], onEmptyRuleSet: "allow" },
		});
		expect(result.rule.onEmptyRuleSet).toBe("allow");
	});

	it("rejects an unrecognized onEmptyRuleSet value", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", secret: "s", validate: true, ...rfc9068 } },
			attribute: { collectors: [] },
			rule: { collectors: [], onEmptyRuleSet: "maybe" },
		});
		expect(result.success).toBe(false);
	});
});
