// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MIN_SECRET_ENTROPY_BYTES } from "#/config/defaults.mjs";
import { describeWeakSecret, measureSecretEntropyBytes } from "#/config/secretEntropy.mjs";

describe("MIN_SECRET_ENTROPY_BYTES", () => {
	it("is 32 bytes (256 bits) — the same floor auth.provider#282 set", () => {
		expect(MIN_SECRET_ENTROPY_BYTES).toBe(32);
	});
});

describe("measureSecretEntropyBytes", () => {
	it("measures an ordinary passphrase by its UTF-8 byte length", () => {
		// '.' is outside both the base64 and base64url alphabets, so the UTF-8
		// reading is the only plausible one.
		expect(measureSecretEntropyBytes("abc.def")).toBe(7);
	});

	it("counts multi-byte UTF-8 characters as their encoded byte length", () => {
		// 5 x 3-byte characters + '.'
		expect(measureSecretEntropyBytes("パスワード.")).toBe(16);
	});

	it("returns 0 for an empty string", () => {
		expect(measureSecretEntropyBytes("")).toBe(0);
	});

	it("measures a one-character secret as one byte", () => {
		expect(measureSecretEntropyBytes("x")).toBe(1);
	});

	it("measures a hex secret on its DECODED length, not its character count", () => {
		const hex = randomBytes(32).toString("hex"); // 64 characters
		expect(hex).toHaveLength(64);
		expect(measureSecretEntropyBytes(hex)).toBe(32);
	});

	it("reads a 32-character hex secret as the 16 bytes it actually carries", () => {
		const hex = randomBytes(16).toString("hex"); // 32 characters, 16 bytes
		expect(measureSecretEntropyBytes(hex)).toBe(16);
		expect(measureSecretEntropyBytes(hex)).toBeLessThan(MIN_SECRET_ENTROPY_BYTES);
	});

	it("measures a base64url secret on its decoded length", () => {
		const b64 = randomBytes(32).toString("base64url"); // 43 characters, unpadded
		expect(b64).toHaveLength(43);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("measures a padded standard-base64 secret on its decoded length", () => {
		const b64 = randomBytes(32).toString("base64"); // 43 body + 1 pad
		expect(b64).toHaveLength(44);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("takes the SMALLEST plausible reading when several decodings apply", () => {
		// All-hex strings are simultaneously valid base64url: 64 characters
		// decode to 32 bytes as hex and 48 as base64url, and the conservative
		// reading is the one an attacker gets to use.
		expect(measureSecretEntropyBytes("0".repeat(64))).toBe(32);
	});

	it("does not read a string whose length no base64 encoding produces as base64", () => {
		// 21 characters: 21 % 4 === 1, which no encoder emits.
		expect(measureSecretEntropyBytes("test-secret-for-e2e--")).toBe(21);
	});

	it("does not read a value that mixes the two base64 alphabets as base64", () => {
		// '+' is standard-only and '-' is URL-safe-only; a value carrying both is
		// not a valid encoding in either, so it reads as its 8 raw bytes.
		expect(measureSecretEntropyBytes("ab+cd-ef")).toBe(8);
	});
});

describe("measureSecretEntropyBytes — base64 padding must be well-formed", () => {
	/*
	 * An encoder emits zero, one or two '=', and only where the body length calls
	 * for it. Trimming any run of '=' would turn a passphrase that merely ends in
	 * equals signs into a "valid" base64 body and score it at three-quarters of
	 * its real length — fail-closed, but a usability trap with no security to
	 * show for it. auth.provider#282 shipped that bug and then fixed it; this
	 * port must not reintroduce it.
	 */

	it("accepts one '=' after a 3-character final group", () => {
		const b64 = randomBytes(32).toString("base64");
		expect(b64.endsWith("=")).toBe(true);
		expect(b64.endsWith("==")).toBe(false);
		expect(measureSecretEntropyBytes(b64)).toBe(32);
	});

	it("accepts two '=' after a 2-character final group", () => {
		const b64 = randomBytes(31).toString("base64");
		expect(b64.endsWith("==")).toBe(true);
		expect(measureSecretEntropyBytes(b64)).toBe(31);
	});

	it("refuses more than two '=' — 'abcd====' is not base64, so it reads as 8 raw bytes", () => {
		expect(measureSecretEntropyBytes("abcd====")).toBe(8);
	});

	it("refuses padding the body length does not call for ('abcd=')", () => {
		expect(measureSecretEntropyBytes("abcd=")).toBe(5);
	});

	it("refuses two '=' after a 3-character group ('abc==')", () => {
		expect(measureSecretEntropyBytes("abc==")).toBe(5);
	});

	it("does not punish a long passphrase that merely ends in equals signs", () => {
		const passphrase = `${"a".repeat(40)}====`;
		expect(passphrase).toHaveLength(44);
		expect(measureSecretEntropyBytes(passphrase)).toBe(44);
		expect(measureSecretEntropyBytes(passphrase)).toBeGreaterThanOrEqual(MIN_SECRET_ENTROPY_BYTES);
	});

	it("returns the raw reading for a value that is only padding", () => {
		expect(measureSecretEntropyBytes("==")).toBe(2);
	});
});

describe("measureSecretEntropyBytes — the values the floor is meant to catch", () => {
	it("reads 32 alphanumerics as the 24 bytes a base64 body carries", () => {
		// [A-Za-z0-9]{32} is a valid base64 body, and an operator who picked 32
		// alphanumerics really does hold only ~190 bits: 62 possibilities per
		// character is ~5.95 bits, not 8.
		expect(measureSecretEntropyBytes("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")).toBe(24);
	});

	it.each(["secret", "your-secret", "s", "test-secret"])(
		"reads the example value %s as short of the floor",
		(value) => {
			expect(measureSecretEntropyBytes(value)).toBeLessThan(MIN_SECRET_ENTROPY_BYTES);
		},
	);

	it("clears the floor on the umbrella E2E's shared secret", () => {
		// o3co/auth's Makefile defines this once for both the provider and this
		// verifier: 43 base64 characters plus one '=' — exactly 32 decoded bytes.
		const e2e = "qmV+afsq/SMZ7hPGs9edVQDvPzNmjXemJNjqti181v0=";
		expect(measureSecretEntropyBytes(e2e)).toBe(32);
		expect(measureSecretEntropyBytes(e2e)).toBeGreaterThanOrEqual(MIN_SECRET_ENTROPY_BYTES);
	});
});

describe("describeWeakSecret", () => {
	it("names the field the operator wrote and the byte count it carries", () => {
		const message = describeWeakSecret("previousSecrets[0].secret", 7);
		expect(message).toContain("previousSecrets[0].secret");
		expect(message).toMatch(/\b7\b/);
		expect(message).toMatch(/at least 32 bytes/i);
	});

	it("tells the operator how to generate a conforming secret", () => {
		expect(describeWeakSecret("secret", 1)).toMatch(/openssl rand -hex 32/);
	});

	it("explains that encoded values are measured on their decoded length", () => {
		expect(describeWeakSecret("secret", 16)).toMatch(/decoded/i);
	});

	it("never echoes the rejected value — it takes only the measurement", () => {
		// The signature is the guarantee: there is no parameter to leak through.
		expect(describeWeakSecret("secret", 19)).not.toContain("hunter2");
	});
});
