// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { MAX_PREVIOUS_SECRETS } from "#/config/defaults.mjs";
import { checkHs256Rotation, parseHs256Rotation } from "#/jwt/hs256Rotation.mjs";

/** 64 hex characters — 32 decoded bytes, the floor auth.provider#282 set. */
const SECRET = "11".repeat(32);
const OLD_SECRET = "22".repeat(32);

const future = "2999-01-01T00:00:00Z";

describe("checkHs256Rotation — the absent case", () => {
	it("treats an omitted previousSecrets as no rotation", () => {
		const result = checkHs256Rotation({ secret: SECRET, previousSecrets: undefined });
		expect(result).toEqual({ ok: true, previousSecrets: [] });
	});

	it("accepts an explicit empty list", () => {
		const result = checkHs256Rotation({ secret: SECRET, previousSecrets: [] });
		expect(result).toEqual({ ok: true, previousSecrets: [] });
	});

	it("refuses null — it is not a second spelling for omitted", () => {
		// A null here was produced rather than written (an unrendered template, a
		// missing env var), so reading it as "nothing is being rotated" would boot
		// a verifier that denies every token signed with the retired secret.
		const result = checkHs256Rotation({ secret: SECRET, previousSecrets: null });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues).toEqual([
				{ path: ["previousSecrets"], message: expect.stringContaining("null is not a spelling") },
			]);
		}
	});

	it("carries a kid through even with no previous secrets", () => {
		const result = checkHs256Rotation({ secret: SECRET, kid: "v1", previousSecrets: [] });
		expect(result).toEqual({ ok: true, kid: "v1", previousSecrets: [] });
	});
});

describe("checkHs256Rotation — shape", () => {
	it("accepts a well-formed entry", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
		});
		expect(result).toEqual({
			ok: true,
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
		});
	});

	it("refuses a previousSecrets value that is not an array", () => {
		const result = checkHs256Rotation({ secret: SECRET, kid: "v1", previousSecrets: "v0" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues).toEqual([
				{ path: ["previousSecrets"], message: expect.stringContaining("must be an array") },
			]);
		}
	});

	// `null` is refused as the whole value, but an entry inside the list is a
	// separate check — `typeof null === "object"`, so it needs its own case.
	it.each([
		["a string", "v0"],
		["null", null],
		["a nested array", []],
	])("refuses an entry that is not an object — %s", (_label, entry) => {
		const result = checkHs256Rotation({ secret: SECRET, kid: "v1", previousSecrets: [entry] });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["previousSecrets", 0]);
		}
	});

	it.each([
		["kid", { kid: "", secret: OLD_SECRET, expiresAt: future }],
		["secret", { kid: "v0", secret: "", expiresAt: future }],
		["expiresAt", { kid: "v0", secret: OLD_SECRET, expiresAt: "" }],
	])("refuses an entry with an empty %s", (field, entry) => {
		const result = checkHs256Rotation({ secret: SECRET, kid: "v1", previousSecrets: [entry] });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["previousSecrets", 0, field]);
		}
	});

	it("refuses an expiresAt that is not a timestamp", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: "next tuesday" }],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.message).toMatch(/not a valid timestamp/);
		}
	});

	it("reports every malformed entry at once", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			kid: "v2",
			previousSecrets: [
				{ kid: "", secret: OLD_SECRET, expiresAt: future },
				{ kid: "v0", secret: OLD_SECRET, expiresAt: "whenever" },
			],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues).toHaveLength(2);
		}
	});
});

describe("checkHs256Rotation — the invariants rotation depends on", () => {
	it("requires a kid for the current secret once a previous one is configured", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues).toEqual([
				{ path: ["kid"], message: expect.stringContaining("kid is required") },
			]);
		}
	});

	it("refuses an empty kid", () => {
		const result = checkHs256Rotation({ secret: SECRET, kid: "" });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["kid"]);
		}
	});

	it("refuses a previous kid that collides with the current one", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			kid: "v0",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.message).toMatch(/duplicate/i);
		}
	});

	it("refuses two previous entries sharing a kid", () => {
		const result = checkHs256Rotation({
			secret: SECRET,
			kid: "v2",
			previousSecrets: [
				{ kid: "v0", secret: OLD_SECRET, expiresAt: future },
				{ kid: "v0", secret: SECRET, expiresAt: future },
			],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["previousSecrets", 1, "kid"]);
		}
	});

	it("caps the list, because a token with no kid is tried against every entry", () => {
		const previousSecrets = Array.from({ length: MAX_PREVIOUS_SECRETS + 1 }, (_, i) => ({
			kid: `v${i}`,
			secret: OLD_SECRET,
			expiresAt: future,
		}));
		const result = checkHs256Rotation({ secret: SECRET, kid: "current", previousSecrets });
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.issues[0]?.path).toEqual(["previousSecrets"]);
			expect(result.issues[0]?.message).toMatch(
				new RegExp(`at most ${MAX_PREVIOUS_SECRETS} entries`),
			);
		}
	});

	it("accepts exactly the cap", () => {
		const previousSecrets = Array.from({ length: MAX_PREVIOUS_SECRETS }, (_, i) => ({
			kid: `v${i}`,
			secret: OLD_SECRET,
			expiresAt: future,
		}));
		const result = checkHs256Rotation({ secret: SECRET, kid: "current", previousSecrets });
		expect(result.ok).toBe(true);
	});
});

describe("parseHs256Rotation", () => {
	it("returns the narrowed rotation config", () => {
		expect(
			parseHs256Rotation({
				secret: SECRET,
				kid: "v1",
				previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
			}),
		).toEqual({
			kid: "v1",
			previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
		});
	});

	it("throws the same message the schema reports, prefixed with the config path", () => {
		expect(() =>
			parseHs256Rotation({
				secret: SECRET,
				previousSecrets: [{ kid: "v0", secret: OLD_SECRET, expiresAt: future }],
			}),
		).toThrow(/^oauth\.jwt\.kid is required/);
	});

	it("names the boundary's own path when one is supplied", () => {
		expect(() => parseHs256Rotation({ secret: SECRET, previousSecrets: 7 }, "jwt")).toThrow(
			/^jwt\.previousSecrets must be an array/,
		);
	});
});
