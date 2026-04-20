// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { AttrPairCompare } from "#/rules/AttrPairCompare.mjs";

describe("AttrPairCompare", () => {
	// ---------------------------------------------------------------------------
	// Happy path: each op at boundary values
	// ---------------------------------------------------------------------------

	it("op=lt: returns true when attr(a) < attr(b) (5 < 10)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "lt", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 5],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=lt: returns false when attr(a) === attr(b) (10 < 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "lt", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 10],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=lt: returns false when attr(a) > attr(b) (15 < 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "lt", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 15],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=le: returns true when attr(a) === attr(b) (10 <= 10)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "le", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 10],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=le: returns true when attr(a) < attr(b) (5 <= 10)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "le", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 5],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=le: returns false when attr(a) > attr(b) (15 <= 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "low", op: "le", b: "high" });
		const attrs: Attributes = new Map<string, unknown>([
			["low", 15],
			["high", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns true when attr(a) > attr(b) (15 > 10)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 15],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=gt: returns false when attr(a) === attr(b) (10 > 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 10],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns false when attr(a) < attr(b) (5 > 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 5],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=ge: returns true when attr(a) === attr(b) (10 >= 10)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 10],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: returns true when attr(a) > attr(b) (15 >= 10)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 15],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: returns false when attr(a) < attr(b) (5 >= 10 is false)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 5],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: attr is not a number
	// ---------------------------------------------------------------------------

	it("returns false when attr(a) is a string (not a number)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", "10"],
			["threshold", 5],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr(b) is a string (not a number)", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 10],
			["threshold", "5"],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time safe-deny: missing attr
	// ---------------------------------------------------------------------------

	it("returns false when attr(a) is missing", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([["threshold", 5]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("returns false when attr(b) is missing", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([["score", 10]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time: NaN attribute → false for all ops
	// ---------------------------------------------------------------------------

	it("op=lt: returns false when attr(a) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "lt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", NaN],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=le: returns false when attr(a) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "le", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", NaN],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns false when attr(a) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", NaN],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=ge: returns false when attr(a) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", NaN],
			["threshold", 10],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=lt: returns false when attr(b) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "lt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 5],
			["threshold", NaN],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=le: returns false when attr(b) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "le", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 5],
			["threshold", NaN],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=gt: returns false when attr(b) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 15],
			["threshold", NaN],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("op=ge: returns false when attr(b) is NaN", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", 15],
			["threshold", NaN],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Evaluation-time: Infinity / -Infinity attributes
	// ---------------------------------------------------------------------------

	it("op=gt: Infinity > 100 returns true", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", Infinity],
			["threshold", 100],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=lt: -Infinity < 0 returns true", () => {
		const rule = new AttrPairCompare({ a: "score", op: "lt", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", -Infinity],
			["threshold", 0],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("op=ge: Infinity >= Infinity returns true", () => {
		const rule = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const attrs: Attributes = new Map<string, unknown>([
			["score", Infinity],
			["threshold", Infinity],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'a'
	// ---------------------------------------------------------------------------

	it("throws when 'a' is undefined", () => {
		expect(
			() => new AttrPairCompare({ a: undefined as unknown as string, op: "gt", b: "threshold" }),
		).toThrow(/AttrPairCompare.*'a'.*(non-empty string|got undefined)/);
	});

	it("throws when 'a' is a non-string (number 42)", () => {
		expect(
			() => new AttrPairCompare({ a: 42 as unknown as string, op: "gt", b: "threshold" }),
		).toThrow(/AttrPairCompare.*'a'.*got number/);
	});

	it("throws when 'a' is an empty string", () => {
		expect(() => new AttrPairCompare({ a: "", op: "gt", b: "threshold" })).toThrow(
			/AttrPairCompare.*'a'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'b'
	// ---------------------------------------------------------------------------

	it("throws when 'b' is undefined", () => {
		expect(
			() => new AttrPairCompare({ a: "score", op: "gt", b: undefined as unknown as string }),
		).toThrow(/AttrPairCompare.*'b'.*(non-empty string|got undefined)/);
	});

	it("throws when 'b' is a non-string (number 42)", () => {
		expect(() => new AttrPairCompare({ a: "score", op: "gt", b: 42 as unknown as string })).toThrow(
			/AttrPairCompare.*'b'.*got number/,
		);
	});

	it("throws when 'b' is an empty string", () => {
		expect(() => new AttrPairCompare({ a: "score", op: "gt", b: "" })).toThrow(
			/AttrPairCompare.*'b'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'op'
	// ---------------------------------------------------------------------------

	it("throws when 'op' is missing (undefined)", () => {
		expect(
			() => new AttrPairCompare({ a: "score", op: undefined as unknown as "lt", b: "threshold" }),
		).toThrow(/AttrPairCompare.*'op'/);
	});

	it("throws when 'op' is not a string (number 42)", () => {
		expect(
			() => new AttrPairCompare({ a: "score", op: 42 as unknown as "lt", b: "threshold" }),
		).toThrow(/AttrPairCompare.*'op'/);
	});

	it("throws when 'op' is an invalid string ('eq')", () => {
		expect(
			() => new AttrPairCompare({ a: "score", op: "eq" as unknown as "lt", b: "threshold" }),
		).toThrow(/AttrPairCompare.*'op'/);
	});

	// ---------------------------------------------------------------------------
	// Construction errors: invalid 'group'
	// ---------------------------------------------------------------------------

	it("throws when 'group' is present but is a non-string (number 42)", () => {
		expect(
			() =>
				new AttrPairCompare({
					a: "score",
					op: "gt",
					b: "threshold",
					group: 42 as unknown as string,
				}),
		).toThrow(/AttrPairCompare.*'group'.*got number/);
	});

	it("throws when 'group' is present but is an empty string", () => {
		expect(() => new AttrPairCompare({ a: "score", op: "gt", b: "threshold", group: "" })).toThrow(
			/AttrPairCompare.*'group'.*empty string/,
		);
	});

	// ---------------------------------------------------------------------------
	// ruleType: default derived from a, op, b
	// ---------------------------------------------------------------------------

	it("derives default ruleType from a, op, and b", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		expect(rule.ruleType).toBe("attr_pair_compare:score:gt:threshold");
	});

	it("distinct op or b produce distinct ruleTypes (AND semantics)", () => {
		const r1 = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		const r2 = new AttrPairCompare({ a: "score", op: "ge", b: "threshold" });
		const r3 = new AttrPairCompare({ a: "score", op: "gt", b: "limit" });
		expect(r1.ruleType).not.toBe(r2.ruleType);
		expect(r1.ruleType).not.toBe(r3.ruleType);
	});

	// ---------------------------------------------------------------------------
	// ruleType: group override
	// ---------------------------------------------------------------------------

	it("uses the provided group string as ruleType, overriding the default", () => {
		const r1 = new AttrPairCompare({ a: "score", op: "gt", b: "threshold", group: "score-check" });
		const r2 = new AttrPairCompare({ a: "score", op: "ge", b: "limit", group: "score-check" });
		expect(r1.ruleType).toBe("score-check");
		expect(r2.ruleType).toBe("score-check");
	});

	// ---------------------------------------------------------------------------
	// code and message fields
	// ---------------------------------------------------------------------------

	it("has code 'attr_compare_violated'", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		expect(rule.code).toBe("attr_compare_violated");
	});

	it("message contains a name, op, and b name", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		expect(rule.message).toContain("score");
		expect(rule.message).toContain("gt");
		expect(rule.message).toContain("threshold");
	});

	it("message starts with a capital letter", () => {
		const rule = new AttrPairCompare({ a: "score", op: "gt", b: "threshold" });
		expect(rule.message[0]).toBe(rule.message[0]?.toUpperCase());
	});
});
