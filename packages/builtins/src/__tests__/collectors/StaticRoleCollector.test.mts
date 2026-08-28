// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_ROLES } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { StaticRoleCollector } from "#/collectors/StaticRoleCollector.mjs";

/**
 * `CollectorContext.signal` is required (#115): a pipeline supplies one per
 * collector, so a hand-built context carries one too. These fixtures are not
 * about cancellation, so it is a signal that never aborts.
 */
const NEVER_CANCELLED = new AbortController().signal;

const stubContext: CollectorContext = {
	subject: {} satisfies SubjectAttributes,
	resource: { raw: "test:1", resourceType: "test", resourceId: "1" },
	action: "read",
	signal: NEVER_CANCELLED,
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
