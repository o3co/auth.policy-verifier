import { describe, expect, it } from "vitest";
import { ATTR_ROLES } from "#/engine/keys.mjs";
import type { CollectorContext } from "#/engine/types.mjs";
import { StaticRoleCollector } from "../StaticRoleCollector.mjs";

const stubContext: CollectorContext = {
	payload: { scopes: [] } as any,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

describe("StaticRoleCollector", () => {
	it("returns configured roles", async () => {
		const roles = [
			{ name: "admin", permissions: ["*"] },
			{ name: "viewer", permissions: ["project:*.perm:read"] },
		];
		const collector = new StaticRoleCollector({ roles });
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_ROLES)).toEqual(roles);
	});

	it("returns empty array when no roles configured", async () => {
		const collector = new StaticRoleCollector({ roles: [] });
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_ROLES)).toEqual([]);
	});
});
