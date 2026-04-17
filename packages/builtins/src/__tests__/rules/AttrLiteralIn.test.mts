import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralIn } from "#/rules/AttrLiteralIn.mjs";

describe("AttrLiteralIn", () => {
	// ---------------------------------------------------------------------------
	// Happy path: attr in set → true
	// ---------------------------------------------------------------------------

	it("returns true when attr is a string in the configured values set", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin", "editor", "viewer"] });
		const attrs: Attributes = new Map<string, unknown>([["role", "editor"]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a number in the configured values set", () => {
		const rule = new AttrLiteralIn({ a: "level", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["level", 2]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a boolean in the configured values set", () => {
		const rule = new AttrLiteralIn({ a: "active", values: [true] });
		const attrs: Attributes = new Map<string, unknown>([["active", true]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Happy path: attr not in set → false
	// ---------------------------------------------------------------------------

	it("returns false when attr is a string not in the configured values set", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		const attrs: Attributes = new Map<string, unknown>([["role", "viewer"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr is a number not in the configured values set", () => {
		const rule = new AttrLiteralIn({ a: "level", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["level", 5]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Type mismatch: values type != attr type → safe-deny (no throw)
	// ---------------------------------------------------------------------------

	it("returns false when values are strings but attr is a number (type mismatch)", () => {
		const rule = new AttrLiteralIn({ a: "x", values: ["a", "b"] });
		const attrs: Attributes = new Map<string, unknown>([["x", 42]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when values are numbers but attr is a string (type mismatch)", () => {
		const rule = new AttrLiteralIn({ a: "x", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["x", "1"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing / null attr
	// ---------------------------------------------------------------------------

	it("returns false when the target attribute is missing", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin"] });
		const attrs: Attributes = new Map<string, unknown>();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the target attribute is null", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin"] });
		const attrs: Attributes = new Map<string, unknown>([["role", null]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(
			() => new AttrLiteralIn({ a: undefined as unknown as string, values: ["x"] }),
		).toThrow(/AttrLiteralIn.*'a'.*(non-empty string|got undefined)/);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrLiteralIn({ a: "", values: ["x"] })).toThrow(
			/AttrLiteralIn.*'a'.*empty string/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(
			() => new AttrLiteralIn({ a: 42 as unknown as string, values: ["x"] }),
		).toThrow(/AttrLiteralIn.*'a'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'values'
	// ---------------------------------------------------------------------------

	it("throws when 'values' is missing (undefined)", () => {
		expect(
			() => new AttrLiteralIn({ a: "role", values: undefined as unknown as string[] }),
		).toThrow(/AttrLiteralIn.*'values'/);
	});

	it("throws when 'values' is not an array (a string)", () => {
		expect(
			() => new AttrLiteralIn({ a: "role", values: "admin" as unknown as string[] }),
		).toThrow(/AttrLiteralIn.*'values'/);
	});

	it("throws when 'values' is an empty array", () => {
		expect(() => new AttrLiteralIn({ a: "role", values: [] })).toThrow(
			/AttrLiteralIn.*'values'/,
		);
	});

	it("throws when 'values' contains null", () => {
		expect(
			() => new AttrLiteralIn({ a: "role", values: [null as unknown as string] }),
		).toThrow(/AttrLiteralIn.*'values'/);
	});

	it("throws when 'values' contains undefined", () => {
		expect(
			() =>
				new AttrLiteralIn({ a: "role", values: [undefined as unknown as string] }),
		).toThrow(/AttrLiteralIn.*'values'/);
	});

	it("throws when 'values' contains mixed types (string and number)", () => {
		expect(
			() => new AttrLiteralIn({ a: "role", values: ["a", 1] as unknown as string[] }),
		).toThrow(/AttrLiteralIn.*'values'.*mixed/);
	});

	it("throws when 'values' contains an object element", () => {
		expect(
			() =>
				new AttrLiteralIn({ a: "role", values: [{}] as unknown as string[] }),
		).toThrow(/AttrLiteralIn.*'values'/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is an empty string", () => {
		expect(
			() => new AttrLiteralIn({ a: "role", values: ["admin"], group: "" }),
		).toThrow(/AttrLiteralIn.*'group'.*empty string/);
	});

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() =>
				new AttrLiteralIn({ a: "role", values: ["admin"], group: 42 as unknown as string }),
		).toThrow(/AttrLiteralIn.*'group'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default includes valuesKey
	// ---------------------------------------------------------------------------

	it("derives default ruleType containing the attribute name and valuesKey", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		expect(rule.ruleType).toMatch(/^attr_literal_in:role:string:2:[0-9a-f]{8}$/);
	});

	it("two instances with same 'a' but different values produce different ruleTypes", () => {
		const r1 = new AttrLiteralIn({ a: "role", values: ["admin"] });
		const r2 = new AttrLiteralIn({ a: "role", values: ["editor"] });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	it("two instances with same 'a' and identical values (same order) produce same ruleType", () => {
		const r1 = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		const r2 = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		expect(r1.ruleType).toBe(r2.ruleType);
	});

	it("two instances with same 'a' and same values in different order produce same ruleType (content-based sort)", () => {
		const r1 = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		const r2 = new AttrLiteralIn({ a: "role", values: ["editor", "admin"] });
		expect(r1.ruleType).toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the valuesKey-based default", () => {
		const r1 = new AttrLiteralIn({ a: "role", values: ["admin"], group: "any-role" });
		const r2 = new AttrLiteralIn({ a: "role", values: ["editor"], group: "any-role" });
		expect(r1.ruleType).toBe("any-role");
		expect(r2.ruleType).toBe("any-role");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_not_in_set'", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin"] });
		expect(rule.code).toBe("attr_not_in_set");
	});

	it("message contains the attribute name, the 'must be one of' phrase, and lists all values", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin", "editor"] });
		expect(rule.message).toContain("role");
		expect(rule.message).toContain("must be one of");
		expect(rule.message).toContain("admin");
		expect(rule.message).toContain("editor");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrLiteralIn({ a: "role", values: ["admin"] });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
