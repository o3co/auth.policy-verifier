import { describe, it, expect } from "vitest";
import { ResourceActionPermissionRuleCollector } from "../ResourceActionPermissionRuleCollector.mjs";
import type { CollectorContext } from "#/engine/types.mjs";

describe("ResourceActionPermissionRuleCollector", () => {
	const collector = new ResourceActionPermissionRuleCollector();

	it("creates a HasPermission rule with resource.perm:action", async () => {
		const ctx: CollectorContext = {
			payload: { scopes: [] } as any,
			resource: { raw: "document:12345", resourceType: "document", resourceId: "12345" },
			action: "read",
		};
		const rules = await collector.collect(ctx);
		expect(rules).toHaveLength(1);
		expect(rules[0].ruleType).toBe("permission");

		const attrs = new Map([["permissions", ["document:12345.perm:read"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});

	it("creates correct permission for nested resources", async () => {
		const ctx: CollectorContext = {
			payload: { scopes: [] } as any,
			resource: { raw: "project:1.member", resourceType: "project_member" },
			action: "update",
		};
		const rules = await collector.collect(ctx);
		const attrs = new Map([["permissions", ["project:1.member.perm:update"]]]);
		expect(rules[0].verify(attrs)).toBe(true);
	});
});
