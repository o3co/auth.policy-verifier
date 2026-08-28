// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	ResourceActionPermissionRuleCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import type { Attributes, CollectorContext, Rule } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import {
	assertRuleIndependentOfContext,
	describeRulePurityConformance,
} from "./conformance/rulePurity.mjs";

const scopeContext: CollectorContext = {
	payload: { sub: "user-1", scope: "read:project write:project" },
	resource: { raw: "project:1", resourceType: "project", resourceId: "1" },
	action: "read",
};

const permissionContext: CollectorContext = {
	payload: { sub: "user-1" },
	resource: { raw: "project:1", resourceType: "project", resourceId: "1" },
	action: "read",
};

describeRulePurityConformance({
	name: "ResourceActionScopeRuleCollector",
	collect: (context) => new ResourceActionScopeRuleCollector().collect(context),
	cases: [
		{
			name: "a request the collected rule passes",
			context: scopeContext,
			attrs: new Map<string, unknown>([["scopes", ["read:project", "write:project"]]]),
		},
		{
			name: "a request the collected rule denies",
			context: scopeContext,
			attrs: new Map<string, unknown>([["scopes", ["read:document"]]]),
		},
		{
			name: "attributes the rule cannot read at all",
			context: scopeContext,
			attrs: new Map<string, unknown>(),
		},
	],
});

describeRulePurityConformance({
	name: "ResourceActionPermissionRuleCollector",
	collect: (context) => new ResourceActionPermissionRuleCollector().collect(context),
	cases: [
		{
			name: "a request the collected rule passes",
			context: permissionContext,
			attrs: new Map<string, unknown>([["permissions", ["project:1.perm:read"]]]),
		},
		{
			name: "a request the collected rule denies",
			context: permissionContext,
			attrs: new Map<string, unknown>([["permissions", ["project:1.perm:write"]]]),
		},
	],
});

/*
 * The suite above only proves the builtins are clean. These cases prove the
 * check is capable of failing — a conformance helper that cannot reject a
 * violation is a green tick, not a guarantee.
 *
 * Both violating shapes below are lifted from real ones: the first is
 * `app.test.mts:50-53` as it stood before #152 (and `metrics.test.mts` before
 * #150), the second is the same mistake made one indirection deeper, where a
 * grep for `ctx.` inside `verify` would not see it.
 */
describe("rule purity conformance — the check itself", () => {
	const attrs: Attributes = new Map([["scopes", ["read:project"]]]);

	it("rejects a rule that reads the collector's context at verify time", async () => {
		const collect = async (ctx: CollectorContext): Promise<Rule[]> => [
			{
				ruleType: "scope",
				code: "invalid_scope",
				message: "Insufficient scope",
				verify(attributes) {
					const scopes = attributes.get("scopes");
					// Reads `attrs` *and* the live request — the shape the old
					// "while ignoring `attrs`" wording could not describe.
					return (
						Array.isArray(scopes) && scopes.includes(`${ctx.action}:${ctx.resource.resourceType}`)
					);
				},
			},
		];

		await expect(assertRuleIndependentOfContext(collect, scopeContext, attrs)).rejects.toThrow(
			/read its collector's context/,
		);
	});

	it("rejects a rule that kept a reference into the context rather than the context", async () => {
		const collect = async (ctx: CollectorContext): Promise<Rule[]> => {
			// Not `ctx` itself — one field of it, held live.
			const resource = ctx.resource;
			const action = ctx.action;
			return [
				{
					ruleType: "scope",
					code: "invalid_scope",
					message: "Insufficient scope",
					verify(attributes) {
						const scopes = attributes.get("scopes");
						return Array.isArray(scopes) && scopes.includes(`${action}:${resource.resourceType}`);
					},
				},
			];
		};

		await expect(assertRuleIndependentOfContext(collect, scopeContext, attrs)).rejects.toThrow(
			/read its collector's context/,
		);
	});

	it("accepts the builtin shape: a comparand copied out at collect time", async () => {
		// `action` and `resourceType` are strings, read once and copied. Nothing
		// live survives into `verify`, which is why this is legal and the two
		// cases above are not.
		const collect = async (ctx: CollectorContext): Promise<Rule[]> => {
			const required = `${ctx.action}:${ctx.resource.resourceType}`;
			return [
				{
					ruleType: "scope",
					code: "invalid_scope",
					message: "Insufficient scope",
					verify(attributes) {
						const scopes = attributes.get("scopes");
						return Array.isArray(scopes) && scopes.includes(required);
					},
				},
			];
		};

		await expect(assertRuleIndependentOfContext(collect, scopeContext, attrs)).resolves.toEqual([
			true,
		]);
	});

	it("hands the collector a stable identity for every object it reads", async () => {
		// The harness must not change the semantics of the thing it is checking.
		// Wrapping each nested object on every access would make
		// `ctx.resource === ctx.resource` false, so a collector that compares or
		// caches a sub-object — an honest thing to do — would fail this suite for
		// a reason that exists only inside the proxy. A gate that reports its own
		// artifacts as violations is one people learn to disbelieve.
		let sameObjectTwice = false;
		let distinctFieldsStayDistinct = false;
		let survivesRoundTrip = false;

		const collect = async (ctx: CollectorContext): Promise<Rule[]> => {
			const first = ctx.resource;
			const second = ctx.resource;
			sameObjectTwice = first === second;
			// Memoization must not collapse two different objects into one proxy.
			distinctFieldsStayDistinct = (ctx.resource as object) !== (ctx.payload as object);
			// Identity holds through a nested read, not just a repeated top-level one.
			survivesRoundTrip = new Set([ctx.resource, ctx.resource, ctx.payload]).size === 2;

			const required = `${ctx.action}:${ctx.resource.resourceType}`;
			return [
				{
					ruleType: "scope",
					code: "invalid_scope",
					message: "Insufficient scope",
					verify(attributes) {
						const scopes = attributes.get("scopes");
						return Array.isArray(scopes) && scopes.includes(required);
					},
				},
			];
		};

		await assertRuleIndependentOfContext(collect, scopeContext, attrs);

		expect(sameObjectTwice).toBe(true);
		expect(distinctFieldsStayDistinct).toBe(true);
		expect(survivesRoundTrip).toBe(true);
	});

	it("rejects a rule that mutates the attributes it is judged against", async () => {
		const collect = async (): Promise<Rule[]> => [
			{
				ruleType: "scope",
				code: "invalid_scope",
				message: "Insufficient scope",
				verify(attributes) {
					// The cast is the point: `ReadonlyAttributes` makes this a compile
					// error for a TypeScript author, and nothing at all for a JavaScript
					// one. The behavioural check has to stand on its own.
					(attributes as Attributes).set("scopes", ["escalated"]);
					return true;
				},
			},
		];

		await expect(
			assertRuleIndependentOfContext(
				collect,
				scopeContext,
				new Map([["scopes", ["read:project"]]]),
			),
		).rejects.toThrow(/mutated the attributes/);
	});

	it("rejects a rule whose answer is not a function of the attributes alone", async () => {
		let calls = 0;
		const collect = async (): Promise<Rule[]> => [
			{
				ruleType: "scope",
				code: "invalid_scope",
				message: "Insufficient scope",
				verify() {
					calls += 1;
					return calls === 1;
				},
			},
		];

		await expect(assertRuleIndependentOfContext(collect, scopeContext, attrs)).rejects.toThrow(
			/not a deterministic function/,
		);
	});
});
