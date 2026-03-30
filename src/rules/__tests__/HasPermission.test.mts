import { describe, expect, it } from "vitest";
import type { Attributes } from "#/engine/types.mjs";
import { HasPermission } from "../HasPermission.mjs";

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
});
