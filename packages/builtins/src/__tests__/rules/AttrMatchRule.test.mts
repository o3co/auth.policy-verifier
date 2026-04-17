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

	it("derives ruleType from the pair of attribute keys by default", () => {
		// Distinct pairs must produce distinct ruleType values. Otherwise
		// evaluate() would OR them together within a single group, which
		// weakens "require both comparisons to pass" intent.
		const r1 = new AttrMatchRule({ a: "userId", b: "sub" });
		const r2 = new AttrMatchRule({ a: "orgId", b: "org" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
		expect(r1.ruleType).toContain("userId");
		expect(r1.ruleType).toContain("sub");
	});

	it("uses the provided group override when set, to enable explicit grouping", () => {
		// When callers want two comparisons to be OR'd together (e.g. match by
		// either DID or email), they opt in by passing the same `group`.
		const r1 = new AttrMatchRule({ a: "x", b: "y", group: "identity" });
		const r2 = new AttrMatchRule({ a: "e", b: "f", group: "identity" });
		expect(r1.ruleType).toBe("identity");
		expect(r2.ruleType).toBe("identity");
	});

	it("has code 'attr_mismatch'", () => {
		expect(rule.code).toBe("attr_mismatch");
	});

	it("message describes the contract (both attrs must be non-empty strings and equal)", () => {
		// The message should make the rule's contract explicit, not just say "do not match",
		// because verify() fails closed on missing, non-string, and empty inputs too.
		expect(rule.message).toContain("x");
		expect(rule.message).toContain("y");
		expect(rule.message).toMatch(/non-empty/i);
		expect(rule.message).toMatch(/equal/i);
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
