import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrPairNotEqual } from "#/rules/AttrPairNotEqual.mjs";

describe("AttrPairNotEqual", () => {
	// ---------------------------------------------------------------------------
	// Happy path: verify() returns true
	// ---------------------------------------------------------------------------

	it("returns true when both attrs are non-empty strings and not equal", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", "bob"],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// verify() returns false
	// ---------------------------------------------------------------------------

	it("returns false when the two strings are equal", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", "alice"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is an empty string", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", ""],
			["owner", "bob"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is an empty string", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", ""],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is a number (non-string)", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", 42],
			["owner", "bob"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is a number (non-string)", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", "alice"],
			["owner", 42],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is missing", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([["owner", "bob"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is missing", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([["subject", "alice"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'a' is null", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const attrs: Attributes = new Map<string, unknown>([
			["subject", null],
			["owner", "bob"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr 'b' is null", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
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
		expect(() => new AttrPairNotEqual({ a: undefined as unknown as string, b: "owner" })).toThrow(
			/AttrPairNotEqual.*'a'.*(non-empty string|got undefined)/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(() => new AttrPairNotEqual({ a: 42 as unknown as string, b: "owner" })).toThrow(
			/AttrPairNotEqual.*'a'.*got number/,
		);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrPairNotEqual({ a: "", b: "owner" })).toThrow(
			/AttrPairNotEqual.*'a'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'b'
	// ---------------------------------------------------------------------------

	it("throws when 'b' is undefined", () => {
		expect(() => new AttrPairNotEqual({ a: "subject", b: undefined as unknown as string })).toThrow(
			/AttrPairNotEqual.*'b'.*(non-empty string|got undefined)/,
		);
	});

	it("throws when 'b' is a non-string (number 42)", () => {
		expect(() => new AttrPairNotEqual({ a: "subject", b: 42 as unknown as string })).toThrow(
			/AttrPairNotEqual.*'b'.*got number/,
		);
	});

	it("throws when 'b' is an empty string", () => {
		expect(() => new AttrPairNotEqual({ a: "subject", b: "" })).toThrow(
			/AttrPairNotEqual.*'b'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() => new AttrPairNotEqual({ a: "subject", b: "owner", group: 42 as unknown as string }),
		).toThrow(/AttrPairNotEqual.*'group'.*got number/);
	});

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrPairNotEqual({ a: "subject", b: "owner", group: "" })).toThrow(
			/AttrPairNotEqual.*'group'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from 'a' and 'b'
	// ---------------------------------------------------------------------------

	it("derives default ruleType from a and b", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		expect(rule.ruleType).toBe("attr_pair_not_equal:subject:owner");
	});

	it("distinct a/b produce distinct default ruleTypes (AND semantics)", () => {
		const r1 = new AttrPairNotEqual({ a: "subject", b: "owner" });
		const r2 = new AttrPairNotEqual({ a: "subject", b: "tenant" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrPairNotEqual({ a: "subject", b: "owner", group: "not-self" });
		const r2 = new AttrPairNotEqual({ a: "subject", b: "creator", group: "not-self" });
		expect(r1.ruleType).toBe("not-self");
		expect(r2.ruleType).toBe("not-self");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_match'", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		expect(rule.code).toBe("attr_match");
	});

	it("message contains 'a' name, 'b' name, and the phrase 'must not equal'", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		expect(rule.message).toContain("subject");
		expect(rule.message).toContain("owner");
		expect(rule.message).toContain("must not equal");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrPairNotEqual({ a: "subject", b: "owner" });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
