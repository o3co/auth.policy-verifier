// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, VerifierPayload } from "@o3co/auth.policy-verifier.core";
import { ATTR_ROLES } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { StaticRoleCollector } from "#/collectors/StaticRoleCollector.mjs";

const stubContext: CollectorContext = {
	payload: {} satisfies VerifierPayload,
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
