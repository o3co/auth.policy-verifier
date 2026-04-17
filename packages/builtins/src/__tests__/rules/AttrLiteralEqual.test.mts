import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralEqual } from "#/rules/AttrLiteralEqual.mjs";

describe("AttrLiteralEqual", () => {
	// ---------------------------------------------------------------------------
	// Happy path: verify() returns true
	// ---------------------------------------------------------------------------

	it("returns true when attr equals the configured string literal", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>([["role", "admin"]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr equals the configured number literal", () => {
		const rule = new AttrLiteralEqual({ a: "age", v: 30 });
		const attrs: Attributes = new Map<string, unknown>([["age", 30]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr equals the configured boolean literal", () => {
		const rule = new AttrLiteralEqual({ a: "verified", v: true });
		const attrs: Attributes = new Map<string, unknown>([["verified", true]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Type mismatch: no coercion
	// ---------------------------------------------------------------------------

	it("returns false when number literal v=30 but attr is the string '30' (no coercion)", () => {
		const rule = new AttrLiteralEqual({ a: "age", v: 30 });
		const attrs: Attributes = new Map<string, unknown>([["age", "30"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when string literal v='true' but attr is the boolean true (no coercion)", () => {
		const rule = new AttrLiteralEqual({ a: "verified", v: "true" });
		const attrs: Attributes = new Map<string, unknown>([["verified", true]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing / null attr
	// ---------------------------------------------------------------------------

	it("returns false when the target attribute is missing", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the target attribute is null", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		const attrs: Attributes = new Map<string, unknown>([["role", null]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(() => new AttrLiteralEqual({ a: undefined as unknown as string, v: "x" })).toThrow(
			/AttrLiteralEqual.*'a'.*(non-empty string|got undefined)/,
		);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrLiteralEqual({ a: "", v: "x" })).toThrow(
			/AttrLiteralEqual.*'a'.*empty string/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(() => new AttrLiteralEqual({ a: 42 as unknown as string, v: "x" })).toThrow(
			/AttrLiteralEqual.*'a'.*got number/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'v'
	// ---------------------------------------------------------------------------

	it("throws when 'v' is null", () => {
		expect(() => new AttrLiteralEqual({ a: "role", v: null as unknown as string })).toThrow(
			/AttrLiteralEqual.*'v'.*got null/,
		);
	});

	it("throws when 'v' is undefined", () => {
		expect(() => new AttrLiteralEqual({ a: "role", v: undefined as unknown as string })).toThrow(
			/AttrLiteralEqual.*'v'.*got undefined/,
		);
	});

	it("throws when 'v' is a plain object ({})", () => {
		expect(() => new AttrLiteralEqual({ a: "role", v: {} as unknown as string })).toThrow(
			/AttrLiteralEqual.*'v'.*got object/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrLiteralEqual({ a: "role", v: "admin", group: "" })).toThrow(
			/AttrLiteralEqual.*'group'.*empty string/,
		);
	});

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() => new AttrLiteralEqual({ a: "role", v: "admin", group: 42 as unknown as string }),
		).toThrow(/AttrLiteralEqual.*'group'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from 'a', 'typeof v', and 'String(v)'
	// ---------------------------------------------------------------------------

	it("derives default ruleType including the type segment for a string literal", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		expect(rule.ruleType).toBe("attr_literal_equal:role:string:admin");
	});

	it("derives default ruleType including the type segment for a number literal", () => {
		const rule = new AttrLiteralEqual({ a: "age", v: 30 });
		expect(rule.ruleType).toBe("attr_literal_equal:age:number:30");
	});

	it("derives default ruleType including the type segment for a boolean literal", () => {
		const rule = new AttrLiteralEqual({ a: "verified", v: true });
		expect(rule.ruleType).toBe("attr_literal_equal:verified:boolean:true");
	});

	it("distinct configs produce distinct default ruleTypes (AND semantics)", () => {
		const r1 = new AttrLiteralEqual({ a: "role", v: "admin" });
		const r2 = new AttrLiteralEqual({ a: "role", v: "editor" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	it("distinguishes literals by type in ruleType (e.g. boolean true vs string 'true')", () => {
		// Regression guard: without the typeof-segment in ruleType, these two
		// rules would share the same default ruleType and the evaluator would
		// silently OR them together, weakening authorization. The type tag
		// keeps them AND-combined as intended.
		const r1 = new AttrLiteralEqual({ a: "status", v: true });
		const r2 = new AttrLiteralEqual({ a: "status", v: "true" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrLiteralEqual({ a: "role", v: "admin", group: "any-admin-role" });
		const r2 = new AttrLiteralEqual({ a: "role", v: "superuser", group: "any-admin-role" });
		expect(r1.ruleType).toBe("any-admin-role");
		expect(r2.ruleType).toBe("any-admin-role");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_not_equal'", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		expect(rule.code).toBe("attr_not_equal");
	});

	it("message contains the attribute name and literal value, and starts with a capital letter", () => {
		const rule = new AttrLiteralEqual({ a: "role", v: "admin" });
		expect(rule.message).toContain("role");
		expect(rule.message).toContain("admin");
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
