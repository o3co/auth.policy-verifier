// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
	DEFAULT_JWKS_CACHE_MAX_AGE_MS,
	DEFAULT_JWKS_COOLDOWN_MS,
	DEFAULT_JWKS_TIMEOUT_MS,
} from "#/config/defaults.mjs";
import { checkJwksUri, parseJwksUri, resolveJwksFetchBounds } from "#/jwt/jwks.mjs";

describe("checkJwksUri — transport security (#109)", () => {
	it("accepts an https URI", () => {
		expect(checkJwksUri("https://auth-provider.test/.well-known/jwks.json").ok).toBe(true);
	});

	it.each([
		"http://localhost:3000/.well-known/jwks.json",
		"http://127.0.0.1:3000/.well-known/jwks.json",
		"http://127.9.9.9/.well-known/jwks.json",
		"http://[::1]:3000/.well-known/jwks.json",
	])("accepts plaintext %s — the loopback carve-out for local development", (uri) => {
		expect(checkJwksUri(uri).ok).toBe(true);
	});

	it("rejects plaintext http on a routable host", () => {
		const result = checkJwksUri("http://auth-provider:3000/.well-known/jwks.json");
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.message).toContain("jwksUri");
			expect(result.message).toContain("https");
			expect(result.message).toContain("loopback");
			// The rejected value belongs in the message: the operator has to find it
			// among several possible sources (config file, env override).
			expect(result.message).toContain("http://auth-provider:3000/.well-known/jwks.json");
		}
	});

	it.each([
		"http://auth-provider.test/jwks.json",
		"http://192.168.0.10/jwks.json",
		"http://128.0.0.1/jwks.json",
	])("rejects plaintext %s", (uri) => {
		expect(checkJwksUri(uri).ok).toBe(false);
	});

	it.each([
		"http://localhost.attacker.test/jwks.json",
		"http://127.0.0.1.attacker.test/jwks.json",
		"http://notlocalhost/jwks.json",
		"http://1270.0.0.1/jwks.json",
	])("rejects %s — a host that only looks like loopback", (uri) => {
		expect(checkJwksUri(uri).ok).toBe(false);
	});

	it.each([
		"file:///etc/jwks.json",
		"ftp://auth-provider.test/jwks.json",
		"ws://localhost:3000/jwks.json",
		"data:application/json,{}",
	])("rejects the non-http(s) scheme in %s", (uri) => {
		expect(checkJwksUri(uri).ok).toBe(false);
	});

	it.each(["auth-provider.test/.well-known/jwks.json", "/.well-known/jwks.json", "", "   "])(
		"rejects %s — not an absolute URL",
		(uri) => {
			const result = checkJwksUri(uri);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.message).toContain("absolute URL");
			}
		},
	);
});

describe("parseJwksUri", () => {
	it("returns the parsed URL for an accepted URI", () => {
		expect(parseJwksUri("https://auth-provider.test/.well-known/jwks.json").href).toBe(
			"https://auth-provider.test/.well-known/jwks.json",
		);
	});

	it("throws the message checkJwksUri reports, so both boundaries say the same thing", () => {
		const uri = "http://auth-provider:3000/.well-known/jwks.json";
		const result = checkJwksUri(uri);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(() => parseJwksUri(uri)).toThrow(result.message);
		}
	});
});

describe("resolveJwksFetchBounds — bounded fetches on the decision path (#109)", () => {
	it("defaults every bound when the config sets none", () => {
		expect(resolveJwksFetchBounds({})).toEqual({
			timeoutDuration: DEFAULT_JWKS_TIMEOUT_MS,
			cooldownDuration: DEFAULT_JWKS_COOLDOWN_MS,
			cacheMaxAge: DEFAULT_JWKS_CACHE_MAX_AGE_MS,
		});
	});

	it("takes the operator's overrides", () => {
		expect(
			resolveJwksFetchBounds({
				jwksTimeoutMs: 1500,
				jwksCooldownMs: 5000,
				jwksCacheMaxAgeMs: 60_000,
			}),
		).toEqual({ timeoutDuration: 1500, cooldownDuration: 5000, cacheMaxAge: 60_000 });
	});

	it("keeps an explicit zero cooldown instead of defaulting it away", () => {
		expect(resolveJwksFetchBounds({ jwksCooldownMs: 0 }).cooldownDuration).toBe(0);
	});
});
