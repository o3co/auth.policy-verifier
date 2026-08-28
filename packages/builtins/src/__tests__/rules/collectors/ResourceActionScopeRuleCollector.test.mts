// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { ResourceActionScopeRuleCollector } from "#/rules/collectors/ResourceActionScopeRuleCollector.mjs";

/**
 * `CollectorContext.signal` is required (#115): a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const makeContext = (resourceType: string, action: string, scope?: string): CollectorContext => ({
	payload: { ...(scope !== undefined ? { scope } : {}) } satisfies VerifierPayload,
	resource: { raw: `${resourceType}:1`, resourceType, resourceId: "1" },
	action,
	signal: NEVER_CANCELLED,
});

describe("ResourceActionScopeRuleCollector", () => {
	const collector = new ResourceActionScopeRuleCollector();

	it("creates a HasScope rule with action:resourceType", async () => {
		const rules = await collector.collect(makeContext("document", "read", "read:document"));
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("scope");

		const attrs = new Map([["scopes", ["read:document"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});

	it("creates correct scope for nested resource types", async () => {
		const ctx: CollectorContext = {
			payload: { scope: "update:project_member" } satisfies VerifierPayload,
			resource: { raw: "project:1.member:2", resourceType: "project_member", resourceId: "2" },
			action: "update",
			signal: NEVER_CANCELLED,
		};
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		const attrs = new Map([["scopes", ["update:project_member"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});

	it("emits a failing scope rule when payload has no scope claim (default-deny)", async () => {
		const ctx = makeContext("document", "read");
		// payload has no scope — a scopeless token must not silently drop the
		// scope group from AND-evaluation, which would authorize by omission.
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("scope");
		expect(rules[0].verify(new Map())).toBe(false);
	});

	it("returns no rules for a scopeless token only when scopeless: skip is opted into", async () => {
		const skipping = new ResourceActionScopeRuleCollector({ scopeless: "skip" });
		const rules = await skipping.collect(makeContext("document", "read"));
		expect(rules).toHaveLength(0);
	});

	it("still emits the scope rule under scopeless: skip when the token carries a scope claim", async () => {
		const skipping = new ResourceActionScopeRuleCollector({ scopeless: "skip" });
		const rules = await skipping.collect(makeContext("document", "read", "read:document"));
		expect(rules).toHaveLength(1);
	});

	it("rejects an unrecognized scopeless option at construction time", () => {
		expect(
			() =>
				new ResourceActionScopeRuleCollector({
					scopeless: "allow",
				} as unknown as { scopeless: "deny" | "skip" }),
		).toThrow(/scopeless/);
	});

	it("returns HasScope rule when payload has scope claim", async () => {
		const ctx: CollectorContext = {
			payload: { scope: "read:document" } satisfies VerifierPayload,
			resource: { raw: "document:1", resourceType: "document", resourceId: "1" },
			action: "read",
			signal: NEVER_CANCELLED,
		};
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("scope");
	});

	it("still generates HasScope rule when scope is empty string", async () => {
		const rules = await collector.collect(makeContext("document", "read", ""));
		expect(rules).toHaveLength(1);
	});

	describe("allowBareScopeRewrite", () => {
		it("does not rewrite a bare granted scope by default", async () => {
			const rules = await collector.collect(makeContext("document", "read", "document"));
			expect(rules[0].verify(new Map([["scopes", ["document"]]]))).toBe(false);
		});

		it("passes the opt-in through to the HasScope rule", async () => {
			const rewriting = new ResourceActionScopeRuleCollector({ allowBareScopeRewrite: true });
			const rules = await rewriting.collect(makeContext("document", "read", "document"));
			expect(rules[0].verify(new Map([["scopes", ["document"]]]))).toBe(true);
		});

		it("keeps matching case-sensitive when the rewrite is opted in", async () => {
			const rewriting = new ResourceActionScopeRuleCollector({ allowBareScopeRewrite: true });
			const rules = await rewriting.collect(makeContext("document", "read", "Document"));
			expect(rules[0].verify(new Map([["scopes", ["Document"]]]))).toBe(false);
		});

		it("rejects a non-boolean allowBareScopeRewrite at construction time", () => {
			expect(
				() =>
					new ResourceActionScopeRuleCollector({
						allowBareScopeRewrite: "yes",
					} as unknown as { allowBareScopeRewrite: boolean }),
			).toThrow(/allowBareScopeRewrite/);
		});

		it("rejects an explicit null allowBareScopeRewrite rather than treating it as unset", () => {
			expect(
				() =>
					new ResourceActionScopeRuleCollector({
						allowBareScopeRewrite: null,
					} as unknown as { allowBareScopeRewrite: boolean }),
			).toThrow(/allowBareScopeRewrite/);
		});

		it("accepts an omitted allowBareScopeRewrite", () => {
			expect(() => new ResourceActionScopeRuleCollector({ scopeless: "deny" })).not.toThrow();
		});
	});
});
