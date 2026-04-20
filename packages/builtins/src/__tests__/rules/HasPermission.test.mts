// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { HasPermission } from "#/rules/HasPermission.mjs";

describe("HasPermission", () => {
	it("passes on exact match", () => {
		const rule = new HasPermission("project:1.perm:read");
		const attrs: Attributes = new Map([["permissions", ["project:1.perm:read"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("fails when permission is missing", () => {
		const rule = new HasPermission("project:1.perm:write");
		const attrs: Attributes = new Map([["permissions", ["project:1.perm:read"]]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("matches wildcard * (permit all)", () => {
		const rule = new HasPermission("project:1.perm:read");
		const attrs: Attributes = new Map([["permissions", ["*"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("matches prefix wildcard: project:*.perm:read", () => {
		const rule = new HasPermission("project:123.perm:read");
		const attrs: Attributes = new Map([["permissions", ["project:*.perm:read"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("matches suffix wildcard: project:1.perm:*", () => {
		const rule = new HasPermission("project:1.perm:read");
		const attrs: Attributes = new Map([["permissions", ["project:1.perm:*"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("is case insensitive", () => {
		const rule = new HasPermission("Project:1.Perm:Read");
		const attrs: Attributes = new Map([["permissions", ["project:1.perm:read"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("checks permissions from roles", () => {
		const rule = new HasPermission("project:1.perm:read");
		const attrs: Attributes = new Map([
			["permissions", []],
			["roles", [{ name: "admin", permissions: ["project:1.perm:read"] }]],
		]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("fails when neither permissions nor roles match", () => {
		const rule = new HasPermission("project:1.perm:write");
		const attrs: Attributes = new Map([
			["permissions", ["project:1.perm:read"]],
			["roles", [{ name: "viewer", permissions: ["project:1.perm:read"] }]],
		]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("has ruleType 'permission'", () => {
		const rule = new HasPermission("project:1.perm:read");
		expect(rule.ruleType).toBe("permission");
	});

	it("has code 'no_permission'", () => {
		const rule = new HasPermission("project:1.perm:read");
		expect(rule.code).toBe("no_permission");
	});

	describe("multi-star wildcard rejection", () => {
		it("does NOT match when granted permission has 2+ wildcards — over-granting via dropped suffix", () => {
			// Bug: "resource*action*required" split("*") → ["resource","action","required"]
			// Destructuring const [prefix, suffix] = ... takes only "resource" and "action",
			// silently dropping "required". The check becomes endsWith("action") instead of
			// endsWith("required"), so "resourceXaction" incorrectly matches even though
			// the granted permission requires a "required" segment after the second wildcard.
			// Fix: reject any granted permission containing 2+ wildcards (return false).
			const rule = new HasPermission("resourceXaction");
			const attrs: Attributes = new Map([["permissions", ["resource*action*required"]]]);
			// "resourceXaction" does NOT satisfy "resource*action*required" (missing "required")
			// but the buggy code returns true because "required" is dropped from suffix
			expect(rule.verify(attrs)).toBe(false);
		});

		it("does NOT match when granted permission has 2+ wildcards (posts.*.write.* vs posts.123.read.all)", () => {
			// Additional case: wildcard in the middle — cross-action access must not be granted
			const rule = new HasPermission("posts.123.read.all");
			const attrs: Attributes = new Map([["permissions", ["posts.*.write.*"]]]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("does NOT match when granted permission has 3 wildcards", () => {
			// "a*b*c*d" split → ["a","b","c","d"]; prefix="a", suffix="b"; "c","d" dropped.
			// "aXb" incorrectly matches when "a*b*c*d" should require segments c and d.
			const rule = new HasPermission("aXb");
			const attrs: Attributes = new Map([["permissions", ["a*b*c*d"]]]);
			expect(rule.verify(attrs)).toBe(false);
		});
	});
});
