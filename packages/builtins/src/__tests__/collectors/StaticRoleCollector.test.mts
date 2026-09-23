// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, Role, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
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

	// #255: the collector answers from what it was given at construction — the
	// list and every role in it. A host that keeps the config and changes it
	// afterwards changes nothing.
	it.each<[string, (config: { roles: Role[] }) => void]>([
		["pushing to the roles array", (c) => c.roles.push({ name: "admin", permissions: ["*"] })],
		["splicing the roles array", (c) => c.roles.splice(0, 1)],
		[
			"replacing the roles field",
			(c) => {
				c.roles = [];
			},
		],
		[
			"renaming a configured role",
			(c) => {
				c.roles[0].name = "admin";
			},
		],
		["pushing to a configured role's permissions", (c) => c.roles[0].permissions.push("*")],
		[
			"replacing a configured role's permissions",
			(c) => {
				c.roles[0].permissions = ["*"];
			},
		],
	])("%s after construction changes nothing it collects (#255)", async (_name, mutate) => {
		const config = { roles: [{ name: "viewer", permissions: ["project:*.perm:read"] }] };
		const collector = new StaticRoleCollector(config);

		mutate(config);

		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_ROLES)).toEqual([
			{ name: "viewer", permissions: ["project:*.perm:read"] },
		]);
	});
});
