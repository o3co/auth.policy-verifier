import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { StaticPermissionCollector } from "#/collectors/StaticPermissionCollector.mjs";

const stubContext: CollectorContext = {
	payload: {} satisfies VerifierPayload,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
};

describe("StaticPermissionCollector", () => {
	it("returns configured permissions", async () => {
		const collector = new StaticPermissionCollector({
			permissions: ["project:*.perm:read", "document:*.perm:write"],
		});
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_PERMISSIONS)).toEqual(["project:*.perm:read", "document:*.perm:write"]);
	});

	it("returns empty array when no permissions configured", async () => {
		const collector = new StaticPermissionCollector({ permissions: [] });
		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_PERMISSIONS)).toEqual([]);
	});
});
