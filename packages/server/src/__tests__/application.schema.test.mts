// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

const baseBody = {
	attribute: { collectors: [] },
	rule: { collectors: [] },
};

describe("AppConfigSchema — JWT algorithm validation", () => {
	it("rejects HS256 without secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", validate: true } },
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
			oauth: { jwt: { algorithm, validate: true } },
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
			oauth: { jwt: { algorithm: "ES384", validate: true, custom: "value" } },
			...baseBody,
		});
		expect(result.success).toBe(true);
	});

	it("accepts HS256 with secret", () => {
		const result = AppConfigSchema.safeParse({
			oauth: { jwt: { algorithm: "HS256", secret: "s", validate: true } },
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
