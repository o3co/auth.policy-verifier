// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { DelegationRangeCollector } from "../../collectors/DelegationRangeCollector.mjs";
import { ATTR_DELEGATION_RANGE } from "../../delegation/range.mjs";

const TYPE = "delegation";

const contextWith = (subject: Record<string, unknown>): CollectorContext =>
	({
		subject,
		resource: { raw: "a:1", resourceType: "a", resourceId: "1" },
		action: "run",
		signal: new AbortController().signal,
	}) as CollectorContext;

describe("DelegationRangeCollector", () => {
	it("promotes the paths of the configured type's authorization_details entries", async () => {
		const collector = new DelegationRangeCollector({ type: TYPE });

		const attrs = await collector.collect(
			contextWith({
				authorization_details: [
					{ type: TYPE, path: "a:1.run" },
					{ type: "payment_initiation", path: "x.run" },
					{ type: TYPE, path: "b.read" },
				],
			}),
		);

		expect(attrs.get(ATTR_DELEGATION_RANGE)).toEqual(["a:1.run", "b.read"]);
	});

	// An entry of the type that is not a path in the grammar narrows the range
	// rather than widening it: it is left out, and a range left with nothing
	// contains nothing.
	it("leaves out an entry of the type whose path is not in the grammar, and writes the range even when nothing is left", async () => {
		const collector = new DelegationRangeCollector({ type: TYPE });

		const attrs = await collector.collect(
			contextWith({
				authorization_details: [
					{ type: TYPE, path: "A.run" },
					{ type: TYPE, path: 7 },
					{ type: TYPE },
				],
			}),
		);

		expect(attrs.get(ATTR_DELEGATION_RANGE)).toEqual([]);
	});

	it.each([
		["no authorization_details", {}],
		[
			"entries of other types only",
			{ authorization_details: [{ type: "payment_initiation", path: "a.run" }] },
		],
		["an empty list", { authorization_details: [] }],
	])("writes no range for a token with %s", async (_label, subject) => {
		const collector = new DelegationRangeCollector({ type: TYPE });

		const attrs = await collector.collect(contextWith(subject));

		expect(attrs.has(ATTR_DELEGATION_RANGE)).toBe(false);
	});

	it.each([
		["an object", { type: TYPE, path: "a.run" }],
		["a string", "a.run"],
		["a list of non-objects", ["a.run"]],
	])(
		"writes an empty range for an authorization_details claim that is %s",
		async (_label, claim) => {
			const attrs = await new DelegationRangeCollector({ type: TYPE }).collect(
				contextWith({ authorization_details: claim }),
			);
			expect(attrs.get(ATTR_DELEGATION_RANGE)).toEqual([]);
		},
	);

	it("reads the configured claim", async () => {
		const collector = new DelegationRangeCollector({ type: TYPE, claim: "ad" });

		const attrs = await collector.collect(contextWith({ ad: [{ type: TYPE, path: "a.run" }] }));

		expect(attrs.get(ATTR_DELEGATION_RANGE)).toEqual(["a.run"]);
	});

	it.each([[undefined], [""], [7]])("refuses to be built without a type (%j)", (type) => {
		expect(() => new DelegationRangeCollector({ type } as never)).toThrow(
			/DelegationRangeCollector: type/,
		);
	});
});
