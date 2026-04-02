import { describe, expect, it } from "vitest";
import type { CollectorContext, VerifierPayload } from "#/engine/types.mjs";
import { ResourceActionScopeRuleCollector } from "../ResourceActionScopeRuleCollector.mjs";

const makeContext = (resourceType: string, action: string): CollectorContext => ({
	payload: {} satisfies VerifierPayload,
	resource: { raw: `${resourceType}:1`, resourceType, resourceId: "1" },
	action,
});

describe("ResourceActionScopeRuleCollector", () => {
	const collector = new ResourceActionScopeRuleCollector();

	it("creates a HasScope rule with action:resourceType", async () => {
		const rules = await collector.collect(makeContext("document", "read"));
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("scope");

		const attrs = new Map([["scopes", ["read:document"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});

	it("creates correct scope for nested resource types", async () => {
		const ctx: CollectorContext = {
			payload: {} satisfies VerifierPayload,
			resource: { raw: "project:1.member:2", resourceType: "project_member", resourceId: "2" },
			action: "update",
		};
		const rules = await collector.collect(ctx);
		const attrs = new Map([["scopes", ["update:project_member"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});
});
