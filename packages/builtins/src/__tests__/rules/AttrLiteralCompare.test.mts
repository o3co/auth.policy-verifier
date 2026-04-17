import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrLiteralCompare } from "#/rules/AttrLiteralCompare.mjs";

describe("AttrLiteralCompare", () => {
	// ---------------------------------------------------------------------------
	// Happy path: each op at boundary values
	// ---------------------------------------------------------------------------

	it("op=lt: returns true when attr < v (5 < 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 5]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=lt: returns false when attr === v (10 < 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 10]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=lt: returns false when attr > v (15 < 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 15]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=le: returns true when attr === v (10 <= 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "le", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 10]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=le: returns true when attr < v (5 <= 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "le", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 5]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=le: returns false when attr > v (15 <= 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "le", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 15]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns true when attr > v (15 > 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 15]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=gt: returns false when attr === v (10 > 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 10]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns false when attr < v (5 > 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 5]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=ge: returns true when attr === v (10 >= 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "ge", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 10]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: returns true when attr > v (15 >= 10)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "ge", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 15]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: returns false when attr < v (5 >= 10 is false)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "ge", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", 5]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: attr is not a number
	// ---------------------------------------------------------------------------

	it("returns false when attr is a string (not a number)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 5 });
		const attrs: Attributes = new Map<string, unknown>([["score", "10"]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr is a boolean (not a number)", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 0 });
		const attrs: Attributes = new Map<string, unknown>([["score", true]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time: NaN attribute → false for all ops
	// ---------------------------------------------------------------------------

	it("op=lt: returns false when attr is NaN", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", NaN]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=le: returns false when attr is NaN", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "le", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", NaN]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns false when attr is NaN", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", NaN]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=ge: returns false when attr is NaN", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "ge", v: 10 });
		const attrs: Attributes = new Map<string, unknown>([["score", NaN]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time: Infinity / -Infinity attributes
	// ---------------------------------------------------------------------------

	it("op=gt: Infinity > 100 returns true", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 100 });
		const attrs: Attributes = new Map<string, unknown>([["score", Infinity]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=lt: -Infinity < 0 returns true", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: 0 });
		const attrs: Attributes = new Map<string, unknown>([["score", -Infinity]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: Infinity >= Infinity returns true", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "ge", v: Infinity });
		const attrs: Attributes = new Map<string, unknown>([["score", Infinity]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing / null attr
	// ---------------------------------------------------------------------------

	it("returns false when the target attribute is missing", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 0 });
		const attrs: Attributes = new Map<string, unknown>();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when the target attribute is null", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 0 });
		const attrs: Attributes = new Map<string, unknown>([["score", null]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(
			() => new AttrLiteralCompare({ a: undefined as unknown as string, op: "gt", v: 0 }),
		).toThrow(/AttrLiteralCompare.*'a'.*(non-empty string|got undefined)/);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrLiteralCompare({ a: "", op: "gt", v: 0 })).toThrow(
			/AttrLiteralCompare.*'a'.*empty string/,
		);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(() => new AttrLiteralCompare({ a: 42 as unknown as string, op: "gt", v: 0 })).toThrow(
			/AttrLiteralCompare.*'a'.*got number/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'v'
	// ---------------------------------------------------------------------------

	it("throws when 'v' is missing (undefined)", () => {
		expect(
			() => new AttrLiteralCompare({ a: "score", op: "gt", v: undefined as unknown as number }),
		).toThrow(/AttrLiteralCompare.*'v'/);
	});

	it("throws when 'v' is null", () => {
		expect(
			() => new AttrLiteralCompare({ a: "score", op: "gt", v: null as unknown as number }),
		).toThrow(/AttrLiteralCompare.*'v'/);
	});

	it("throws when 'v' is a string", () => {
		expect(
			() => new AttrLiteralCompare({ a: "score", op: "gt", v: "10" as unknown as number }),
		).toThrow(/AttrLiteralCompare.*'v'/);
	});

	it("throws when 'v' is a boolean", () => {
		expect(
			() => new AttrLiteralCompare({ a: "score", op: "gt", v: true as unknown as number }),
		).toThrow(/AttrLiteralCompare.*'v'/);
	});

	it("throws when 'v' is a plain object", () => {
		expect(
			() => new AttrLiteralCompare({ a: "score", op: "gt", v: {} as unknown as number }),
		).toThrow(/AttrLiteralCompare.*'v'/);
	});

	it("throws when 'v' is NaN (fail-fast at construction)", () => {
		expect(() => new AttrLiteralCompare({ a: "score", op: "gt", v: NaN })).toThrow(
			/AttrLiteralCompare.*'v'.*NaN/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'op'
	// ---------------------------------------------------------------------------

	it("throws when 'op' is missing (undefined)", () => {
		expect(
			() =>
				new AttrLiteralCompare({
					a: "score",
					op: undefined as unknown as "lt",
					v: 0,
				}),
		).toThrow(/AttrLiteralCompare.*'op'/);
	});

	it("throws when 'op' is not a string (number)", () => {
		expect(
			() =>
				new AttrLiteralCompare({
					a: "score",
					op: 42 as unknown as "lt",
					v: 0,
				}),
		).toThrow(/AttrLiteralCompare.*'op'/);
	});

	it("throws when 'op' is an invalid string ('eq')", () => {
		expect(
			() =>
				new AttrLiteralCompare({
					a: "score",
					op: "eq" as unknown as "lt",
					v: 0,
				}),
		).toThrow(/AttrLiteralCompare.*'op'/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrLiteralCompare({ a: "score", op: "gt", v: 0, group: "" })).toThrow(
			/AttrLiteralCompare.*'group'.*empty string/,
		);
	});

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() =>
				new AttrLiteralCompare({
					a: "score",
					op: "gt",
					v: 0,
					group: 42 as unknown as string,
				}),
		).toThrow(/AttrLiteralCompare.*'group'.*got number/);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from a, op, v
	// ---------------------------------------------------------------------------

	it("derives default ruleType from a, op, and v", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		expect(rule.ruleType).toBe("attr_literal_compare:score:gt:10");
	});

	it("derives default ruleType for negative v", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: -5 });
		expect(rule.ruleType).toBe("attr_literal_compare:score:lt:-5");
	});

	it("derives default ruleType for Infinity v", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "lt", v: Infinity });
		expect(rule.ruleType).toBe("attr_literal_compare:score:lt:Infinity");
	});

	it("distinct op or v produce distinct ruleTypes (AND semantics)", () => {
		const r1 = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		const r2 = new AttrLiteralCompare({ a: "score", op: "ge", v: 10 });
		const r3 = new AttrLiteralCompare({ a: "score", op: "gt", v: 20 });
		expect(r1.ruleType).not.toBe(r2.ruleType);
		expect(r1.ruleType).not.toBe(r3.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrLiteralCompare({ a: "score", op: "gt", v: 10, group: "score-check" });
		const r2 = new AttrLiteralCompare({ a: "score", op: "ge", v: 11, group: "score-check" });
		expect(r1.ruleType).toBe("score-check");
		expect(r2.ruleType).toBe("score-check");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_compare_violated'", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		expect(rule.code).toBe("attr_compare_violated");
	});

	it("message contains the attribute name, op, and v", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		expect(rule.message).toContain("score");
		expect(rule.message).toContain("gt");
		expect(rule.message).toContain("10");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrLiteralCompare({ a: "score", op: "gt", v: 10 });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
