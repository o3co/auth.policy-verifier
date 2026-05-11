// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
	applyCompare,
	COMPARE_OPS,
	computeValuesKey,
	fnv1a64,
	requireAttrName,
	requireCompareOp,
	requireHomogeneousLiteralArray,
	requireLiteralValue,
	requireNumber,
	requireOptionalGroup,
} from "#/rules/_sharedValidation.mjs";

// ---------------------------------------------------------------------------
// requireAttrName
// ---------------------------------------------------------------------------

describe("requireAttrName", () => {
	it("returns the input string when value is a valid non-empty string", () => {
		expect(requireAttrName("MyClass", "a", "role")).toBe("role");
	});

	it("returns the input string for fieldName 'b'", () => {
		expect(requireAttrName("MyClass", "b", "score")).toBe("score");
	});

	it("throws with className and fieldName 'a' in message when value is undefined", () => {
		expect(() => requireAttrName("MyClass", "a", undefined)).toThrow(
			/MyClass.*'a'.*non-empty string.*got undefined/,
		);
	});

	it("throws with className and fieldName 'b' in message when value is undefined", () => {
		expect(() => requireAttrName("MyClass", "b", undefined)).toThrow(
			/MyClass.*'b'.*non-empty string.*got undefined/,
		);
	});

	it("throws with 'empty string' in message when value is ''", () => {
		expect(() => requireAttrName("MyClass", "a", "")).toThrow(/MyClass.*'a'.*got empty string/);
	});

	it("throws with 'got number' in message when value is 42", () => {
		expect(() => requireAttrName("MyClass", "a", 42)).toThrow(/MyClass.*'a'.*got number/);
	});

	it("throws with 'null' in message when value is null", () => {
		expect(() => requireAttrName("MyClass", "a", null)).toThrow(/null/);
	});

	it("throws when value contains ':' (reserved as ruleType separator)", () => {
		// Regression guard for an authorization-weakening bug: with ':' allowed,
		// (a="x:y", b="z") and (a="x", b="y:z") would both produce the same
		// `attr_pair_equal:x:y:z` default ruleType and be silently OR-combined
		// by the evaluator. Fail-fast at construction instead.
		expect(() => requireAttrName("MyClass", "a", "name:space")).toThrow(
			/must not contain ':'.*got 'name:space'/,
		);
	});
});

// ---------------------------------------------------------------------------
// requireLiteralValue
// ---------------------------------------------------------------------------

describe("requireLiteralValue", () => {
	it("returns the value when it is a string", () => {
		expect(requireLiteralValue("MyClass", "v", "hello")).toBe("hello");
	});

	it("returns the value when it is a number", () => {
		expect(requireLiteralValue("MyClass", "v", 42)).toBe(42);
	});

	it("returns the value when it is a boolean", () => {
		expect(requireLiteralValue("MyClass", "v", false)).toBe(false);
	});

	it("throws with 'null' in message when value is null", () => {
		expect(() => requireLiteralValue("MyClass", "v", null)).toThrow(/null/);
	});

	it("throws with 'undefined' in message when value is undefined", () => {
		expect(() => requireLiteralValue("MyClass", "v", undefined)).toThrow(/undefined/);
	});

	it("throws with 'object' in message when value is a plain object", () => {
		expect(() => requireLiteralValue("MyClass", "v", {})).toThrow(/object/);
	});

	it("throws with 'object' in message when value is an array (typeof [] === 'object')", () => {
		expect(() => requireLiteralValue("MyClass", "v", [])).toThrow(/object/);
	});

	it("throws on NaN (NaN === NaN is false; would invert Equal/NotEqual rules)", () => {
		// Regression guard for an authorization-weakening bug: with NaN accepted,
		// AttrLiteralNotEqual({ v: NaN }) would always pass for any numeric
		// attribute because `x !== NaN` is always true. Must fail-fast in
		// construction instead.
		expect(() => requireLiteralValue("MyClass", "v", Number.NaN)).toThrow(/must not be NaN/);
	});
});

// ---------------------------------------------------------------------------
// requireNumber
// ---------------------------------------------------------------------------

describe("requireNumber", () => {
	it("returns 0 (zero)", () => {
		expect(requireNumber("MyClass", "v", 0)).toBe(0);
	});

	it("returns -0 (negative zero)", () => {
		expect(requireNumber("MyClass", "v", -0)).toBe(-0);
	});

	it("returns a large finite number", () => {
		expect(requireNumber("MyClass", "v", 1e308)).toBe(1e308);
	});

	it("returns Infinity without throwing (Infinity is a valid number per spec)", () => {
		expect(requireNumber("MyClass", "v", Infinity)).toBe(Infinity);
	});

	it("returns -Infinity without throwing", () => {
		expect(requireNumber("MyClass", "v", -Infinity)).toBe(-Infinity);
	});

	it("throws on NaN with message matching /must not be NaN/", () => {
		expect(() => requireNumber("MyClass", "v", NaN)).toThrow(/must not be NaN/);
	});

	it("throws on a string '42' with message containing 'got string'", () => {
		expect(() => requireNumber("MyClass", "v", "42")).toThrow(/got string/);
	});

	it("throws on null with message containing 'null'", () => {
		expect(() => requireNumber("MyClass", "v", null)).toThrow(/null/);
	});

	it("throws on undefined with message containing 'undefined'", () => {
		expect(() => requireNumber("MyClass", "v", undefined)).toThrow(/undefined/);
	});
});

// ---------------------------------------------------------------------------
// requireHomogeneousLiteralArray
// ---------------------------------------------------------------------------

describe("requireHomogeneousLiteralArray", () => {
	it("returns a non-empty all-string array", () => {
		const arr = ["a", "b", "c"];
		expect(requireHomogeneousLiteralArray("MyClass", arr)).toEqual(arr);
	});

	it("returns a non-empty all-number array", () => {
		const arr = [1, 2, 3];
		expect(requireHomogeneousLiteralArray("MyClass", arr)).toEqual(arr);
	});

	it("returns a non-empty all-boolean array", () => {
		const arr = [true, false];
		expect(requireHomogeneousLiteralArray("MyClass", arr)).toEqual(arr);
	});

	it("throws with 'got string' when value is not an array", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", "abc")).toThrow(/got string/);
	});

	it("throws with 'undefined' when value is undefined", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", undefined)).toThrow(/undefined/);
	});

	it("throws with 'null' when value is null", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", null)).toThrow(/null/);
	});

	it("throws with 'non-empty array' on empty array", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", [])).toThrow(/non-empty array/);
	});

	it("throws with 'null' when an element is null", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", [null])).toThrow(/null/);
	});

	it("throws with 'undefined' when an element is undefined", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", [undefined])).toThrow(/undefined/);
	});

	it("throws with 'object' when an element is an object", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", [{}])).toThrow(/object/);
	});

	it("throws with mixed types message for ['a', 1] (left-to-right Set insertion order)", () => {
		expect(() => requireHomogeneousLiteralArray("MyClass", ["a", 1])).toThrow(
			/mixed types \[string, number\]/,
		);
	});

	it("throws when an element is NaN (would silently mismatch AttrLiteralIn/NotIn)", () => {
		// Regression guard: AttrLiteralIn uses strict equality against each element;
		// a NaN element could never match any attribute value because NaN !== NaN.
		// Must fail-fast at construction rather than ship an always-false element.
		expect(() => requireHomogeneousLiteralArray("MyClass", [1, Number.NaN, 3])).toThrow(
			/must not contain NaN/,
		);
	});
});

// ---------------------------------------------------------------------------
// requireCompareOp
// ---------------------------------------------------------------------------

describe("requireCompareOp", () => {
	it("returns 'lt' for valid op 'lt'", () => {
		expect(requireCompareOp("MyClass", "lt")).toBe("lt");
	});

	it("returns 'le' for valid op 'le'", () => {
		expect(requireCompareOp("MyClass", "le")).toBe("le");
	});

	it("returns 'gt' for valid op 'gt'", () => {
		expect(requireCompareOp("MyClass", "gt")).toBe("gt");
	});

	it("returns 'ge' for valid op 'ge'", () => {
		expect(requireCompareOp("MyClass", "ge")).toBe("ge");
	});

	it("throws on invalid string 'eq' with message listing valid ops joined by ' | '", () => {
		expect(() => requireCompareOp("MyClass", "eq")).toThrow(/lt \| le \| gt \| ge/);
	});

	it("throws on empty string '' with message listing valid ops", () => {
		expect(() => requireCompareOp("MyClass", "")).toThrow(/lt \| le \| gt \| ge/);
	});

	it("throws on symbolic string '<' with message listing valid ops", () => {
		expect(() => requireCompareOp("MyClass", "<")).toThrow(/lt \| le \| gt \| ge/);
	});

	it("throws on number 42 with message containing the type label", () => {
		expect(() => requireCompareOp("MyClass", 42)).toThrow(/got number/);
	});

	it("throws on null with message containing the type label", () => {
		expect(() => requireCompareOp("MyClass", null)).toThrow(/null/);
	});

	it("throws on undefined with message containing the type label", () => {
		expect(() => requireCompareOp("MyClass", undefined)).toThrow(/undefined/);
	});
});

// ---------------------------------------------------------------------------
// requireOptionalGroup
// ---------------------------------------------------------------------------

describe("requireOptionalGroup", () => {
	it("returns undefined when value is undefined", () => {
		expect(requireOptionalGroup("MyClass", undefined)).toBeUndefined();
	});

	it("returns the input string when value is a non-empty string", () => {
		expect(requireOptionalGroup("MyClass", "my-group")).toBe("my-group");
	});

	it("throws with 'empty string' message on ''", () => {
		expect(() => requireOptionalGroup("MyClass", "")).toThrow(/empty string/);
	});

	it("throws with 'got number' message on 42", () => {
		expect(() => requireOptionalGroup("MyClass", 42)).toThrow(/got number/);
	});

	it("throws with 'null' in message on null", () => {
		expect(() => requireOptionalGroup("MyClass", null)).toThrow(/null/);
	});
});

// ---------------------------------------------------------------------------
// fnv1a64
// ---------------------------------------------------------------------------

describe("fnv1a64", () => {
	it("returns 16 lowercase hex characters", () => {
		expect(fnv1a64("hello")).toMatch(/^[0-9a-f]{16}$/);
	});

	it("zero-pads short outputs to 16 characters", () => {
		// Empty string hashes to the FNV offset basis (0xcbf29ce484222325).
		// Any input whose hash happens to fit in fewer than 16 hex digits
		// must still be padded — assert via length.
		expect(fnv1a64("").length).toBe(16);
		expect(fnv1a64("a").length).toBe(16);
	});

	it("is deterministic: the same input produces the same output", () => {
		expect(fnv1a64("abc")).toBe(fnv1a64("abc"));
	});

	it("differentiates inputs: distinct strings produce distinct outputs (sanity check)", () => {
		expect(fnv1a64("a")).not.toBe(fnv1a64("b"));
	});

	it("matches the FNV-1a 64-bit reference vector for the empty string (0xcbf29ce484222325)", () => {
		// Per http://www.isthe.com/chongo/tech/comp/fnv/ the FNV-1a 64-bit
		// hash of an empty input is the offset basis itself. This pins the
		// constants and the BigInt arithmetic so an accidental edit (e.g.
		// swapping prime / basis, or dropping the 64-bit mask) is detected
		// even when other tests still pass on derived data.
		expect(fnv1a64("")).toBe("cbf29ce484222325");
	});

	it("matches the published FNV-1a 64-bit reference vector for 'foobar' (0x85944171f73967e8)", () => {
		// Second pinning vector from the FNV reference test set, defending
		// against any single-constant typo that empty-string alone would miss.
		expect(fnv1a64("foobar")).toBe("85944171f73967e8");
	});

	it("does not collide on the 32-bit FNV-1a counterexample ('v0jxp73609' vs 'jtrl7v0818102')", () => {
		// These two short strings collide under FNV-1a 32-bit (both → 0x832c03b4),
		// which was the empirical evidence used during code review to reject the
		// 32-bit variant. Pin that they remain distinct under the 64-bit hash so
		// any future width regression is caught immediately.
		expect(fnv1a64("v0jxp73609")).not.toBe(fnv1a64("jtrl7v0818102"));
	});
});

// ---------------------------------------------------------------------------
// computeValuesKey
// ---------------------------------------------------------------------------

describe("computeValuesKey", () => {
	it("returns a string matching /{type}:{count}:{16-hex-chars}/ format", () => {
		expect(computeValuesKey(["admin"])).toMatch(/^(string|number|boolean):[0-9]+:[0-9a-f]{16}$/);
	});

	it("sort determinism: same content in different order produces the same key", () => {
		expect(computeValuesKey(["b", "a"])).toBe(computeValuesKey(["a", "b"]));
	});

	it("count discrimination: ['a'] !== ['a', 'b'] (distinct content → distinct key)", () => {
		expect(computeValuesKey(["a"])).not.toBe(computeValuesKey(["a", "b"]));
	});

	it("dedup parity: ['a'] === ['a', 'a'] (duplicates do not affect the Set-based rule behavior, so they must not affect ruleType either)", () => {
		// AttrLiteralIn / AttrLiteralNotIn use `new Set(values)` for verify(),
		// so duplicate elements have no semantic effect. The ruleType must
		// mirror that — otherwise two logically-equivalent rules would be
		// placed in different evaluator groups and be AND-combined, when
		// the caller intended them to be OR-combined (shared ruleType).
		expect(computeValuesKey(["a"])).toBe(computeValuesKey(["a", "a"]));
	});

	it("content discrimination: ['a', 'b'] !== ['a', 'c'] (hash differs)", () => {
		expect(computeValuesKey(["a", "b"])).not.toBe(computeValuesKey(["a", "c"]));
	});

	it("type segment correctness: string array starts with 'string:'", () => {
		expect(computeValuesKey(["admin"])).toMatch(/^string:/);
	});

	it("type segment correctness: number array starts with 'number:'", () => {
		expect(computeValuesKey([1])).toMatch(/^number:/);
	});

	it("type segment correctness: boolean array starts with 'boolean:'", () => {
		expect(computeValuesKey([true])).toMatch(/^boolean:/);
	});

	it("type divergence: computeValuesKey(['1']) !== computeValuesKey([1]) (type segment differs)", () => {
		expect(computeValuesKey(["1"])).not.toBe(computeValuesKey([1]));
	});

	it("separator collision guard: ['a,b', 'c'] !== ['a', 'b,c'] (values containing commas do not collide)", () => {
		// Regression guard: a naive implementation of the form
		//   values.map(String).sort().join(",")
		// would produce the same string "a,b,c" for both inputs and thus the
		// same ruleType. That would cause the evaluator to OR what the caller
		// meant as two independent set constraints, weakening authorization.
		// The canonical form JSON.stringify-es each element before joining,
		// so quotes/escapes disambiguate the element boundary.
		expect(computeValuesKey(["a,b", "c"])).not.toBe(computeValuesKey(["a", "b,c"]));
	});

	it("pure / referentially transparent: two calls with the same input return the same string", () => {
		const input = ["x", "y", "z"];
		expect(computeValuesKey(input)).toBe(computeValuesKey(input));
	});
});

// ---------------------------------------------------------------------------
// applyCompare
// ---------------------------------------------------------------------------

describe("applyCompare", () => {
	describe("op=lt", () => {
		it("returns true when left < right (1 < 2)", () => {
			expect(applyCompare("lt", 1, 2)).toBe(true);
		});

		it("returns false when left === right (2 < 2 is false)", () => {
			expect(applyCompare("lt", 2, 2)).toBe(false);
		});

		it("returns false when left > right (3 < 2 is false)", () => {
			expect(applyCompare("lt", 3, 2)).toBe(false);
		});

		it("edge: -Infinity < 0 returns true", () => {
			expect(applyCompare("lt", -Infinity, 0)).toBe(true);
		});
	});

	describe("op=le", () => {
		it("returns true when left < right (1 <= 2)", () => {
			expect(applyCompare("le", 1, 2)).toBe(true);
		});

		it("returns true when left === right (2 <= 2)", () => {
			expect(applyCompare("le", 2, 2)).toBe(true);
		});

		it("returns false when left > right (3 <= 2 is false)", () => {
			expect(applyCompare("le", 3, 2)).toBe(false);
		});

		it("edge: 0 >= -0 returns true (ge symmetry check; 0 <= -0 also true)", () => {
			expect(applyCompare("le", 0, -0)).toBe(true);
		});
	});

	describe("op=gt", () => {
		it("returns true when left > right (3 > 2)", () => {
			expect(applyCompare("gt", 3, 2)).toBe(true);
		});

		it("returns false when left === right (2 > 2 is false)", () => {
			expect(applyCompare("gt", 2, 2)).toBe(false);
		});

		it("returns false when left < right (1 > 2 is false)", () => {
			expect(applyCompare("gt", 1, 2)).toBe(false);
		});

		it("edge: Infinity > 1e308 returns true", () => {
			expect(applyCompare("gt", Infinity, 1e308)).toBe(true);
		});
	});

	describe("op=ge", () => {
		it("returns true when left > right (3 >= 2)", () => {
			expect(applyCompare("ge", 3, 2)).toBe(true);
		});

		it("returns true when left === right (2 >= 2)", () => {
			expect(applyCompare("ge", 2, 2)).toBe(true);
		});

		it("returns false when left < right (1 >= 2 is false)", () => {
			expect(applyCompare("ge", 1, 2)).toBe(false);
		});

		it("edge: 0 >= -0 returns true", () => {
			expect(applyCompare("ge", 0, -0)).toBe(true);
		});
	});
});

// ---------------------------------------------------------------------------
// COMPARE_OPS
// ---------------------------------------------------------------------------

describe("COMPARE_OPS", () => {
	it("exposes exactly 4 values", () => {
		expect(COMPARE_OPS).toHaveLength(4);
	});

	it("contains 'lt', 'le', 'gt', 'ge' in order", () => {
		expect(COMPARE_OPS).toEqual(["lt", "le", "gt", "ge"]);
	});
});
