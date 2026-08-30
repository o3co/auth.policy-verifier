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

	// #155: matching is exact and case-sensitive, the discipline #116 (HasScope)
	// and #117 (DotNotationResourceParser) argued for every identifier
	// vocabulary. The parser preserves case, so `Project:1` and `project:1` are
	// two resources — a permission rule collapsing them was the exact
	// "one resource on one side, two on the other" split #117 closed.
	it("does not match across case: required Project:1 vs granted project:1", () => {
		const rule = new HasPermission("Project:1.Perm:Read");
		const attrs: Attributes = new Map([["permissions", ["project:1.perm:read"]]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("does not match across case in the other direction either", () => {
		const rule = new HasPermission("project:1.perm:read");
		const attrs: Attributes = new Map([["permissions", ["Project:1.perm:READ"]]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("compares the literal halves around a wildcard case-sensitively", () => {
		const rule = new HasPermission("project:1.perm:read");
		// The wildcard is written structure and still honoured; the cased
		// prefix is not the prefix the requirement carries.
		const attrs: Attributes = new Map([["permissions", ["Project:*"]]]);
		expect(rule.verify(attrs)).toBe(false);
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

	// #180: the halves around the wildcard must not overlap in the required
	// permission. `startsWith(prefix) && endsWith(suffix)` alone lets one
	// character satisfy both halves — "posts.*.read" matched "posts.read",
	// where the single "." was counted as the prefix's trailing "." and the
	// suffix's leading "." at once. An over-grant, the failure direction that
	// matters in an authorization service.
	describe("wildcard halves must not overlap (#180)", () => {
		it("does NOT match when one character would satisfy both halves: posts.*.read vs posts.read", () => {
			const rule = new HasPermission("posts.read");
			const attrs: Attributes = new Map([["permissions", ["posts.*.read"]]]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("does NOT match when the required permission is shorter than the two halves: a*a vs a", () => {
			const rule = new HasPermission("a");
			const attrs: Attributes = new Map([["permissions", ["a*a"]]]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("still matches a real middle segment: posts.*.read vs posts.123.read", () => {
			const rule = new HasPermission("posts.123.read");
			const attrs: Attributes = new Map([["permissions", ["posts.*.read"]]]);
			expect(rule.verify(attrs)).toBe(true);
		});

		it("matches when the halves touch without sharing: a*a vs aa — the wildcard may match empty", () => {
			// The guard refuses shared characters, not an empty middle: each
			// character of the required permission counts toward at most one half.
			const rule = new HasPermission("aa");
			const attrs: Attributes = new Map([["permissions", ["a*a"]]]);
			expect(rule.verify(attrs)).toBe(true);
		});
	});

	// #180 (related): roles reach this rule from collectors, so a store-backed
	// role collector can hand back shapes the operator-config
	// StaticRoleCollector never produces. Malformed entries never match and
	// never throw — the discipline HasScope already applies to non-string
	// scope values. Before the guard, an undefined `permissions` reached
	// `match` and threw, turning one bad row in a role store into a 500 deny.
	describe("malformed role data never matches and never throws (#180)", () => {
		it("ignores a role whose permissions is missing", () => {
			const rule = new HasPermission("posts.read");
			const attrs: Attributes = new Map([["roles", [{ name: "broken" }]]]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("ignores a role whose permissions is not an array — malformed shapes are not half-honoured", () => {
			const rule = new HasPermission("posts.read");
			const attrs: Attributes = new Map([
				["roles", [{ name: "broken", permissions: "posts.read" }]],
			]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("ignores a null role entry", () => {
			const rule = new HasPermission("posts.read");
			const attrs: Attributes = new Map([["roles", [null]]]);
			expect(rule.verify(attrs)).toBe(false);
		});

		it("ignores non-string entries among granted permissions and still finds a string match", () => {
			const rule = new HasPermission("posts.read");
			const attrs: Attributes = new Map([["permissions", [42, null, "posts.read"]]]);
			expect(rule.verify(attrs)).toBe(true);
		});
	});
});
