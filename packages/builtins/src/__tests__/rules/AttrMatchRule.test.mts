import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrMatchRule } from "#/rules/AttrMatchRule.mjs";

describe("AttrMatchRule", () => {
	const rule = new AttrMatchRule({ a: "x", b: "y" });

	it("returns true when both attrs are non-empty strings and equal", () => {
		const attrs: Attributes = new Map([
			["x", "same"],
			["y", "same"],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns false when the two attrs differ", () => {
		const attrs: Attributes = new Map([
			["x", "foo"],
			["y", "bar"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the first attr is missing", () => {
		const attrs: Attributes = new Map([["y", "same"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the second attr is missing", () => {
		const attrs: Attributes = new Map([["x", "same"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when either attr is a non-string value", () => {
		const attrs: Attributes = new Map<string, unknown>([
			["x", 42],
			["y", 42],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when either attr is an empty string", () => {
		const attrs: Attributes = new Map([
			["x", ""],
			["y", ""],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("has ruleType 'attr_match' and code 'attr_mismatch'", () => {
		expect(rule.ruleType).toBe("attr_match");
		expect(rule.code).toBe("attr_mismatch");
	});

	it("message mentions both attribute keys", () => {
		expect(rule.message).toContain("x");
		expect(rule.message).toContain("y");
	});
});
