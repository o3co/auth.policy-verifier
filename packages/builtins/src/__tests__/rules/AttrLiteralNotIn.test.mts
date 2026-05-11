// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralNotIn } from "#/rules/AttrLiteralNotIn.mjs";

describe("AttrLiteralNotIn", () => {
	// ---------------------------------------------------------------------------
	// Happy path: attr not in set → true
	// ---------------------------------------------------------------------------

	it("returns true when attr is a string NOT in the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		const attrs: Attributes = new Map<string, unknown>([["role", "viewer"]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a number NOT in the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "level", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["level", 5]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("returns true when attr is a boolean NOT in the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "active", values: [false] });
		const attrs: Attributes = new Map<string, unknown>([["active", true]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Happy path: attr in set → false
	// ---------------------------------------------------------------------------

	it("returns false when attr is a string IN the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		const attrs: Attributes = new Map<string, unknown>([["role", "admin"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr is a number IN the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "level", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["level", 2]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr is a boolean IN the configured values set", () => {
		const rule = new AttrLiteralNotIn({ a: "active", values: [true] });
		const attrs: Attributes = new Map<string, unknown>([["active", true]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Type mismatch: safe-deny (no coercion)
	// ---------------------------------------------------------------------------

	it("returns false when values are strings but attr is a number (type mismatch)", () => {
		const rule = new AttrLiteralNotIn({ a: "x", values: ["a", "b"] });
		const attrs: Attributes = new Map<string, unknown>([["x", 42]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when values are numbers but attr is a string (type mismatch)", () => {
		const rule = new AttrLiteralNotIn({ a: "x", values: [1, 2, 3] });
		const attrs: Attributes = new Map<string, unknown>([["x", "1"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing / null attr
	// ---------------------------------------------------------------------------

	it("returns false when the target attribute is missing", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		const attrs: Attributes = new Map<string, unknown>();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the target attribute is null", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		const attrs: Attributes = new Map<string, unknown>([["role", null]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(
			() => new AttrLiteralNotIn({ a: undefined as unknown as string, values: ["x"] }),
		).toThrow(/AttrLiteralNotIn.*'a'.*(non-empty string|got undefined)/);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrLiteralNotIn({ a: "", values: ["x"] })).toThrow(
			/AttrLiteralNotIn.*'a'.*empty string/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(() => new AttrLiteralNotIn({ a: 42 as unknown as string, values: ["x"] })).toThrow(
			/AttrLiteralNotIn.*'a'.*got number/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'values'
	// ---------------------------------------------------------------------------

	it("throws when 'values' is missing (undefined)", () => {
		expect(
			() => new AttrLiteralNotIn({ a: "role", values: undefined as unknown as string[] }),
		).toThrow(/AttrLiteralNotIn.*'values'/);
	});

	it("throws when 'values' is not an array (a string)", () => {
		expect(
			() => new AttrLiteralNotIn({ a: "role", values: "admin" as unknown as string[] }),
		).toThrow(/AttrLiteralNotIn.*'values'/);
	});

	it("throws when 'values' is an empty array", () => {
		expect(() => new AttrLiteralNotIn({ a: "role", values: [] })).toThrow(
			/AttrLiteralNotIn.*'values'/,
		);
	});

	it("throws when 'values' contains null", () => {
		expect(() => new AttrLiteralNotIn({ a: "role", values: [null as unknown as string] })).toThrow(
			/AttrLiteralNotIn.*'values'/,
		);
	});

	it("throws when 'values' contains undefined", () => {
		expect(
			() => new AttrLiteralNotIn({ a: "role", values: [undefined as unknown as string] }),
		).toThrow(/AttrLiteralNotIn.*'values'/);
	});

	it("throws when 'values' contains mixed types (string and number)", () => {
		expect(
			() => new AttrLiteralNotIn({ a: "role", values: ["a", 1] as unknown as string[] }),
		).toThrow(/AttrLiteralNotIn.*'values'.*mixed/);
	});

	it("throws when 'values' contains an object element", () => {
		expect(() => new AttrLiteralNotIn({ a: "role", values: [{}] as unknown as string[] })).toThrow(
			/AttrLiteralNotIn.*'values'/,
		);
	});

	it("throws when 'values' contains NaN", () => {
		// A NaN element could never match any numeric attribute (NaN !== NaN),
		// so including it in a "deny these" list is a silent policy mistake.
		expect(() => new AttrLiteralNotIn({ a: "score", values: [1, Number.NaN, 3] })).toThrow(
			/AttrLiteralNotIn.*must not contain NaN/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrLiteralNotIn({ a: "role", values: ["admin"], group: "" })).toThrow(
			/AttrLiteralNotIn.*'group'.*empty string/,
		);
	});

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() => new AttrLiteralNotIn({ a: "role", values: ["admin"], group: 42 as unknown as string }),
		).toThrow(/AttrLiteralNotIn.*'group'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default includes valuesKey
	// ---------------------------------------------------------------------------

	it("derives default ruleType containing the attribute name and valuesKey", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		expect(rule.ruleType).toMatch(/^attr_literal_not_in:role:string:2:[0-9a-f]{16}$/);
	});

	it("two instances with same 'a' but different values produce different ruleTypes", () => {
		const r1 = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		const r2 = new AttrLiteralNotIn({ a: "role", values: ["editor"] });
		expect(r1.ruleType).not.toBe(r2.ruleType);
	});

	it("two instances with same 'a' and identical values (same order) produce same ruleType", () => {
		const r1 = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		const r2 = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		expect(r1.ruleType).toBe(r2.ruleType);
	});

	it("two instances with same 'a' and same values in different order produce same ruleType (content-based sort)", () => {
		const r1 = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		const r2 = new AttrLiteralNotIn({ a: "role", values: ["editor", "admin"] });
		expect(r1.ruleType).toBe(r2.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the valuesKey-based default", () => {
		const r1 = new AttrLiteralNotIn({ a: "role", values: ["admin"], group: "not-admin-set" });
		const r2 = new AttrLiteralNotIn({ a: "role", values: ["editor"], group: "not-admin-set" });
		expect(r1.ruleType).toBe("not-admin-set");
		expect(r2.ruleType).toBe("not-admin-set");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_in_set'", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		expect(rule.code).toBe("attr_in_set");
	});

	it("message contains the attribute name and lists all values", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin", "editor"] });
		expect(rule.message).toContain("role");
		expect(rule.message).toContain("admin");
		expect(rule.message).toContain("editor");
	});

	it("message contains 'must not be one of'", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		expect(rule.message).toContain("must not be one of");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrLiteralNotIn({ a: "role", values: ["admin"] });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
