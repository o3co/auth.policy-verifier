import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralNotEqual } from "#/rules/AttrLiteralNotEqual.mjs";

describe("AttrLiteralNotEqual", () => {
	// ---------------------------------------------------------------------------
	// Happy path: verify() returns true (attr present, type matches, not equal)
	// ---------------------------------------------------------------------------

	it("returns true when attr is a different string than the configured literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>([["role", "editor"]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a different number than the configured literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "age", v: 30 });
		const attrs: Attributes = new Map<string, unknown>([["age", 25]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a different boolean than the configured literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "verified", v: true });
		const attrs: Attributes = new Map<string, unknown>([["verified", false]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// verify() returns false when attr equals the literal
	// ---------------------------------------------------------------------------

	it("returns false when attr equals the configured string literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>([["role", "admin"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr equals the configured number literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "age", v: 30 });
		const attrs: Attributes = new Map<string, unknown>([["age", 30]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr equals the configured boolean literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "verified", v: false });
		const attrs: Attributes = new Map<string, unknown>([["verified", false]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Type mismatch: safe-deny (no coercion)
	// ---------------------------------------------------------------------------

	it("returns false when number literal v=30 but attr is the string '30' (no coercion)", () => {
		const rule = new AttrLiteralNotEqual({ a: "age", v: 30 });
		const attrs: Attributes = new Map<string, unknown>([["age", "30"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when string literal v='true' but attr is the boolean true (no coercion)", () => {
		const rule = new AttrLiteralNotEqual({ a: "verified", v: "true" });
		const attrs: Attributes = new Map<string, unknown>([["verified", true]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing / null attr
	// ---------------------------------------------------------------------------

	it("returns false when the target attribute is missing", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the target attribute is null", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>([["role", null]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(() => new AttrLiteralNotEqual({ a: undefined as unknown as string, v: "x" })).toThrow(
			/AttrLiteralNotEqual.*'a'.*(non-empty string|got undefined)/,
		);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrLiteralNotEqual({ a: "", v: "x" })).toThrow(
			/AttrLiteralNotEqual.*'a'.*empty string/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(() => new AttrLiteralNotEqual({ a: 42 as unknown as string, v: "x" })).toThrow(
			/AttrLiteralNotEqual.*'a'.*got number/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'v'
	// ---------------------------------------------------------------------------

	it("throws when 'v' is null", () => {
		expect(() => new AttrLiteralNotEqual({ a: "role", v: null as unknown as string })).toThrow(
			/AttrLiteralNotEqual.*'v'.*got null/,
		);
	});

	it("throws when 'v' is undefined", () => {
		expect(() => new AttrLiteralNotEqual({ a: "role", v: undefined as unknown as string })).toThrow(
			/AttrLiteralNotEqual.*'v'.*got undefined/,
		);
	});

	it("throws when 'v' is a plain object ({})", () => {
		expect(() => new AttrLiteralNotEqual({ a: "role", v: {} as unknown as string })).toThrow(
			/AttrLiteralNotEqual.*'v'.*got object/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrLiteralNotEqual({ a: "role", v: "admin", group: "" })).toThrow(
			/AttrLiteralNotEqual.*'group'.*empty string/,
		);
	});

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() => new AttrLiteralNotEqual({ a: "role", v: "admin", group: 42 as unknown as string }),
		).toThrow(/AttrLiteralNotEqual.*'group'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from 'a' and 'v'
	// ---------------------------------------------------------------------------

	it("derives default ruleType from a and v for a string literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		expect(rule.ruleType).toBe("attr_literal_not_equal:role:admin");
	});

	it("derives default ruleType from a and v for a number literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "age", v: 30 });
		expect(rule.ruleType).toBe("attr_literal_not_equal:age:30");
	});

	it("derives default ruleType from a and v for a boolean literal", () => {
		const rule = new AttrLiteralNotEqual({ a: "verified", v: true });
		expect(rule.ruleType).toBe("attr_literal_not_equal:verified:true");
	});

	it("distinct configs produce distinct default ruleTypes (AND semantics)", () => {
		const r1 = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		const r2 = new AttrLiteralNotEqual({ a: "role", v: "editor" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrLiteralNotEqual({ a: "role", v: "banned", group: "not-banned" });
		const r2 = new AttrLiteralNotEqual({ a: "role", v: "blocked", group: "not-banned" });
		expect(r1.ruleType).toBe("not-banned");
		expect(r2.ruleType).toBe("not-banned");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_equal'", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		expect(rule.code).toBe("attr_equal");
	});

	it("message contains the attribute name and literal value, and starts with a capital letter", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		expect(rule.message).toContain("role");
		expect(rule.message).toContain("admin");
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});

	it("message contains 'must not equal'", () => {
		const rule = new AttrLiteralNotEqual({ a: "role", v: "admin" });
		expect(rule.message).toContain("must not equal");
	});
});
