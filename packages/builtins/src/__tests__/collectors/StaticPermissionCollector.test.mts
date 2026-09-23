// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { StaticPermissionCollector } from "#/collectors/StaticPermissionCollector.mjs";

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

describe("StaticPermissionCollector", () => {
	it.each([
		["missing", undefined],
		["null", null],
		["a number", 42],
		["a plain object", {}],
	])("throws a TypeError at construction when `permissions` is %s (#255)", (_label, value) => {
		expect(() => new StaticPermissionCollector({ permissions: value } as never)).toThrow(TypeError);
	});

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

	// #255: the collector answers from what it was given at construction. A
	// host that keeps the config and changes it afterwards changes nothing.
	it.each<[string, (config: { permissions: string[] }) => void]>([
		["pushing to the permissions array", (c) => c.permissions.push("*")],
		["splicing the permissions array", (c) => c.permissions.splice(0, 1, "*")],
		[
			"replacing the permissions field",
			(c) => {
				c.permissions = ["*"];
			},
		],
	])("%s after construction changes nothing it collects (#255)", async (_name, mutate) => {
		const config = { permissions: ["project:*.perm:read", "document:*.perm:write"] };
		const collector = new StaticPermissionCollector(config);

		mutate(config);

		const attrs = await collector.collect(stubContext);
		expect(attrs.get(ATTR_PERMISSIONS)).toEqual(["project:*.perm:read", "document:*.perm:write"]);
	});
});
