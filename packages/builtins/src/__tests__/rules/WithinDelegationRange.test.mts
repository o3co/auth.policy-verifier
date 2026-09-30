// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { ATTR_DELEGATION_RANGE } from "../../keys.mjs";
import { WithinDelegationRange } from "../../rules/WithinDelegationRange.mjs";

const attrsWith = (range: unknown) =>
	new Map<string, unknown>(range === undefined ? [] : [[ATTR_DELEGATION_RANGE, range]]);

describe("WithinDelegationRange", () => {
	it("passes when an entry of the range contains the requested path", () => {
		const rule = new WithinDelegationRange("a:1.b:2.run");
		expect(rule.verify(attrsWith(["x.read", "a:1.b"]))).toBe(true);
	});

	it("fails when no entry contains it", () => {
		const rule = new WithinDelegationRange("a:1.b:2.run");
		expect(rule.verify(attrsWith(["a:2.b", "a:1.c"]))).toBe(false);
	});

	it.each([
		["no range", undefined],
		["an empty range", []],
		["a range that is not a list", "a:1.b"],
		["a range of non-strings", [7, null]],
	])("fails on %s", (_label, range) => {
		expect(new WithinDelegationRange("a:1.run").verify(attrsWith(range))).toBe(false);
	});

	it("fails for a requested path outside the grammar, whatever the range", () => {
		expect(new WithinDelegationRange("A:1.run").verify(attrsWith(["A"]))).toBe(false);
	});

	it("restricts: it narrows what the policies allow and is no reason to allow", () => {
		expect(new WithinDelegationRange("a:1.run").restricts).toBe(true);
	});

	it("names itself and the requested path", () => {
		const rule = new WithinDelegationRange("a:1.run");
		expect(rule.ruleType).toBe("delegation_range");
		expect(rule.code).toBe("outside_delegation_range");
		expect(rule.message).toContain("a:1.run");
	});
});
