// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * The delegation-range path grammar and its containment rule
 * (`delegation/range.mts`), as the provider-verifier claims contract states
 * them: a path is `(type(:id)?.)*action`, and an entry contains a path when it
 * is a segment-wise prefix of it, a segment without an id containing the same
 * type with any id. Nothing is normalized: a path is compared as written.
 */
import { describe, expect, it } from "vitest";
import { parseRangePath, rangeContains } from "../../delegation/range.mjs";

describe("parseRangePath", () => {
	it.each([
		["run"],
		["a.run"],
		["a:1.run"],
		["a:1.b:2.c:3.run"],
		["doc:x%2Fy.read"],
		["a:A-z_~9.run"],
		["a_1:x.b2.run_now"],
	])("accepts %j", (path) => {
		expect(parseRangePath(path)).not.toBeNull();
	});

	it.each([
		[""],
		["A.run"],
		["a.Run"],
		["1a.run"],
		["a:.run"],
		["a:1"],
		["a..run"],
		[".run"],
		["run."],
		["a:1:2.run"],
		["a:x%2f.run"],
		["a:x%2.run"],
		["a:x%ZZ.run"],
		["a:x y.run"],
		["a:x/y.run"],
		["a: 1.run"],
	])("refuses %j", (path) => {
		expect(parseRangePath(path)).toBeNull();
	});

	it("keeps each element's type and id as written", () => {
		expect(parseRangePath("a:1.b.run")).toEqual([
			{ type: "a", id: "1" },
			{ type: "b" },
			{ type: "run" },
		]);
	});
});

describe("rangeContains", () => {
	it.each([
		// The contract's own example.
		["a:1.b", "a:1.b:2.c:3.run", true],
		["a:1.b", "a:1.b.run", true],
		["a:1.b:2.run", "a:1.b:2.run", true],
		["a.run", "a:1.run", true],
		// Prefix, segment by segment: what lies under an entry is contained.
		["a:1.run", "a:1.run.more", true],
		["a:1.b:2.run", "a:1.b:3.run", false],
		["a:1.b.run", "a:2.b:1.run", false],
		["a:1.run", "a.run", false],
		["a:1.b.c.run", "a:1.b.run", false],
		["a:1.b", "a:1.c.run", false],
		["a:1.run", "a:1.read", false],
		// Compared as written: an id's encoding is part of it.
		["doc:x%2Fy.read", "doc:x%2Fy.read", true],
		["doc:x%2Fy.read", "doc:x/y.read", false],
	])("%j contains %j: %s", (entry, path, contained) => {
		expect(rangeContains(entry, path)).toBe(contained);
	});

	it.each([
		["A.run", "A.run"],
		["a:1.run", "a:1:2.run"],
		["", "a.run"],
	])("contains nothing when either side is outside the grammar: %j, %j", (entry, path) => {
		expect(rangeContains(entry, path)).toBe(false);
	});
});
