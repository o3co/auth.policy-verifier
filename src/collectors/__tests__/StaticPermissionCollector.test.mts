import { describe, it, expect } from "vitest";
import { StaticPermissionCollector } from "../StaticPermissionCollector.mjs";
import { ATTR_PERMISSIONS } from "#/engine/keys.mjs";
import type { CollectorContext } from "#/engine/types.mjs";

const stubContext: CollectorContext = {
	payload: { scopes: [] } as any,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

describe("StaticPermissionCollector", () => {
	it("returns configured permissions", async () => {
		const collector = new StaticPermissionCollector({
			permissions: ["project:*.perm:read", "document:*.perm:write"],
		});
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_PERMISSIONS)).toEqual([
			"project:*.perm:read",
			"document:*.perm:write",
		]);
	});

	it("returns empty array when no permissions configured", async () => {
		const collector = new StaticPermissionCollector({ permissions: [] });
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_PERMISSIONS)).toEqual([]);
	});
});
