import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrPairEqual } from "#/rules/AttrPairEqual.mjs";

describe("AttrPairEqual", () => {
	// ---------------------------------------------------------------------------
	// Happy path: verify() returns true
	// ---------------------------------------------------------------------------

	it("returns true when both attrs are equal non-empty strings", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", "alice"],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// verify() returns false
	// ---------------------------------------------------------------------------

	it("returns false when the two strings are different", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", "bob"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is an empty string", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", ""],
			["owner", "alice"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is an empty string", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", ""],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is a number (non-string)", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", 42],
			["owner", "alice"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is a number (non-string)", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", 42],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is missing", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([["owner", "alice"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is missing", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([["subject", "alice"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is null", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", null],
			["owner", "alice"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is null", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", null],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(
			() => new AttrPairEqual({ a: undefined as unknown as string, b: "owner" }),
		).toThrow(/AttrPairEqual.*'a'.*(non-empty string|got undefined)/);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(
			() => new AttrPairEqual({ a: 42 as unknown as string, b: "owner" }),
		).toThrow(/AttrPairEqual.*'a'.*got number/);
	});

	it("throws when 'a' is an empty string", () => {
		expect(
			() => new AttrPairEqual({ a: "", b: "owner" }),
		).toThrow(/AttrPairEqual.*'a'.*empty string/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'b'
	// ---------------------------------------------------------------------------

	it("throws when 'b' is undefined", () => {
		expect(
			() => new AttrPairEqual({ a: "subject", b: undefined as unknown as string }),
		).toThrow(/AttrPairEqual.*'b'.*(non-empty string|got undefined)/);
	});

	it("throws when 'b' is a non-string (number 42)", () => {
		expect(
			() => new AttrPairEqual({ a: "subject", b: 42 as unknown as string }),
		).toThrow(/AttrPairEqual.*'b'.*got number/);
	});

	it("throws when 'b' is an empty string", () => {
		expect(
			() => new AttrPairEqual({ a: "subject", b: "" }),
		).toThrow(/AttrPairEqual.*'b'.*empty string/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() => new AttrPairEqual({ a: "subject", b: "owner", group: 42 as unknown as string }),
		).toThrow(/AttrPairEqual.*'group'.*got number/);
	});

	it("throws when 'group' is present but is an empty string", () => {
		expect(
			() => new AttrPairEqual({ a: "subject", b: "owner", group: "" }),
		).toThrow(/AttrPairEqual.*'group'.*empty string/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from 'a' and 'b'
	// ---------------------------------------------------------------------------

	it("derives default ruleType from a and b", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		expect(rule.ruleType).toBe("attr_pair_equal:subject:owner");
	});

	it("distinct a/b produce distinct default ruleTypes (AND semantics)", () => {
		const r1 = new AttrPairEqual({ a: "subject", b: "owner" });
		const r2 = new AttrPairEqual({ a: "subject", b: "tenant" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrPairEqual({ a: "subject", b: "owner", group: "identity-check" });
		const r2 = new AttrPairEqual({ a: "subject", b: "creator", group: "identity-check" });
		expect(r1.ruleType).toBe("identity-check");
		expect(r2.ruleType).toBe("identity-check");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_mismatch'", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		expect(rule.code).toBe("attr_mismatch");
	});

	it("message contains 'a' name, 'b' name, and the phrase 'must equal'", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		expect(rule.message).toContain("subject");
		expect(rule.message).toContain("owner");
		expect(rule.message).toContain("must equal");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrPairEqual({ a: "subject", b: "owner" });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
