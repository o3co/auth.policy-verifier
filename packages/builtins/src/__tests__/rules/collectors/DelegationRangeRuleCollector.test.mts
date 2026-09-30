// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { ATTR_DELEGATION_RANGE } from "../../../keys.mjs";
import { DelegationRangeRuleCollector } from "../../../rules/collectors/DelegationRangeRuleCollector.mjs";

const TYPE = "delegation";

const contextWith = (
	subject: Record<string, unknown>,
	raw = "a:1.b:2",
	action = "run",
): CollectorContext =>
	({
		subject,
		resource: { raw, resourceType: "a.b", resourceId: "2" },
		action,
		signal: new AbortController().signal,
	}) as CollectorContext;

describe("DelegationRangeRuleCollector", () => {
	// A token without a range is evaluated as it is without this collector.
	it.each([
		["no authorization_details", {}],
		[
			"entries of other types only",
			{ authorization_details: [{ type: "payment_initiation", path: "a.run" }] },
		],
		["an empty list", { authorization_details: [] }],
	])("emits no rule for a token with %s", async (_label, subject) => {
		const rules = await new DelegationRangeRuleCollector({ type: TYPE }).collect(
			contextWith(subject),
		);
		expect(rules).toEqual([]);
	});

	it("emits one rule for the requested path — the resource, then the action — when the token has a range", async () => {
		const rules = await new DelegationRangeRuleCollector({ type: TYPE }).collect(
			contextWith({ authorization_details: [{ type: TYPE, path: "a:1.b" }] }),
		);

		expect(rules).toHaveLength(1);
		expect(rules[0].verify(new Map([[ATTR_DELEGATION_RANGE, ["a:1.b"]]]))).toBe(true);
		expect(rules[0].verify(new Map([[ATTR_DELEGATION_RANGE, ["a:2.b"]]]))).toBe(false);
		expect(rules[0].message).toContain("a:1.b:2.run");
	});

	// Present however malformed: an entry of the type whose path cannot be read
	// still makes the token one with a range, so the rule is emitted and fails.
	it("emits the rule for a token whose only entry of the type is malformed", async () => {
		const rules = await new DelegationRangeRuleCollector({ type: TYPE }).collect(
			contextWith({ authorization_details: [{ type: TYPE, path: "A.run" }] }),
		);
		expect(rules).toHaveLength(1);
		expect(rules[0].verify(new Map([[ATTR_DELEGATION_RANGE, []]]))).toBe(false);
	});

	it("reads the configured claim", async () => {
		const rules = await new DelegationRangeRuleCollector({ type: TYPE, claim: "ad" }).collect(
			contextWith({ ad: [{ type: TYPE, path: "a.run" }] }),
		);
		expect(rules).toHaveLength(1);
	});

	it.each([[undefined], [""], [7]])("refuses to be built without a type (%j)", (type) => {
		expect(() => new DelegationRangeRuleCollector({ type } as never)).toThrow(
			/DelegationRangeRuleCollector: type/,
		);
	});

	// The action is one element of the grammar. An action that is several —
	// `report.delete` — would re-split the joined path, and a request on the
	// parent would read as one on a child the range contains.
	it.each([["report.delete"], ["report:1.delete"], ["Run"], [""]])(
		"denies an action that is not one action of the grammar (%j), whatever the range",
		async (action) => {
			const rules = await new DelegationRangeRuleCollector({ type: TYPE }).collect(
				contextWith({ authorization_details: [{ type: TYPE, path: "a:1.report" }] }, "a:1", action),
			);

			expect(rules).toHaveLength(1);
			expect(rules[0].verify(new Map([[ATTR_DELEGATION_RANGE, ["a:1.report", "a:1"]]]))).toBe(
				false,
			);
		},
	);

	// RFC 9396 carries the entries as a list. A claim present in another shape
	// is malformed, not absent: the token keeps a range, and it contains nothing.
	it.each([
		["an object", { type: TYPE, path: "a.run" }],
		["a string", "a.run"],
		["a list of non-objects", ["a.run"]],
		["null", null],
		["a list holding a list", [[{ type: TYPE, path: "a.run" }]]],
	])("emits the rule for an authorization_details claim that is %s", async (_label, claim) => {
		const rules = await new DelegationRangeRuleCollector({ type: TYPE }).collect(
			contextWith({ authorization_details: claim }),
		);
		expect(rules).toHaveLength(1);
	});
});
