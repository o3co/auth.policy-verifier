// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, SubjectAttributes } from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { StaticPermissionCollector } from "#/collectors/StaticPermissionCollector.mjs";
import { HasPermission } from "#/rules/HasPermission.mjs";

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
	// #264: only an array is accepted. A string is iterable, so a copy by
	// spread would split it into characters — and a lone "*" among them is a
	// grant-all to HasPermission.
	it.each([
		["missing", undefined],
		["null", null],
		["a number", 42],
		["a plain object", {}],
		["a string", "posts.*"],
		["a lone wildcard string", "*"],
	])(
		"refuses at construction a `permissions` that is %s, with a TypeError naming the field (#264)",
		(_label, value) => {
			const construct = () => new StaticPermissionCollector({ permissions: value } as never);
			expect(construct).toThrow(TypeError);
			expect(construct).toThrow("StaticPermissionCollector: permissions must be an array");
		},
	);

	it("cannot be configured into granting every permission with a string `permissions` (#264)", async () => {
		// The misconfiguration the issue describes, where `[ "posts.*" ]` was
		// meant. Split into characters it collected a lone "*", which
		// HasPermission honours as grant-all; refused at construction, it
		// never reaches a rule.
		const grants = async () => {
			const collector = new StaticPermissionCollector({ permissions: "posts.*" as never });
			const attrs = await collector.collect(stubContext);
			return new HasPermission("admin.delete").verify(attrs);
		};
		await expect(grants()).rejects.toThrow(TypeError);
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
