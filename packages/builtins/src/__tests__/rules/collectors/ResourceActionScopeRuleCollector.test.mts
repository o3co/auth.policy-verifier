// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { ResourceActionScopeRuleCollector } from "#/rules/collectors/ResourceActionScopeRuleCollector.mjs";

const makeContext = (resourceType: string, action: string, scope?: string): CollectorContext => ({
	payload: { ...(scope !== undefined ? { scope } : {}) } satisfies VerifierPayload,
	resource: { raw: `${resourceType}:1`, resourceType, resourceId: "1" },
	action,
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
		};
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		const attrs = new Map([["scopes", ["update:project_member"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});

	it("returns no rules when payload has no scope claim", async () => {
		const ctx = makeContext("document", "read");
		// payload has no scope — simulates DID JWT
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(0);
	});

	it("returns HasScope rule when payload has scope claim", async () => {
		const ctx: CollectorContext = {
			payload: { scope: "read:document" } satisfies VerifierPayload,
			resource: { raw: "document:1", resourceType: "document", resourceId: "1" },
			action: "read",
		};
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("scope");
	});

	it("still generates HasScope rule when scope is empty string", async () => {
		const rules = await collector.collect(makeContext("document", "read", ""));
		expect(rules).toHaveLength(1);
	});
});
