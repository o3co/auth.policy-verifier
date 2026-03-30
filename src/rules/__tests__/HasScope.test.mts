import { describe, it, expect } from "vitest";
import { HasScope } from "../HasScope.mjs";
import type { Attributes } from "#/engine/types.mjs";

describe("HasScope", () => {
	it("passes when scope matches exactly", () => {
		const rule = new HasScope("read:user");
		const attrs: Attributes = new Map([["scopes", ["read:user"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("fails when scope does not match", () => {
		const rule = new HasScope("write:user");
		const attrs: Attributes = new Map([["scopes", ["read:user"]]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("normalizes scope without action to read:{resource}", () => {
		const rule = new HasScope("read:user");
		const attrs: Attributes = new Map([["scopes", ["user"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("is case insensitive", () => {
		const rule = new HasScope("READ:User");
		const attrs: Attributes = new Map([["scopes", ["read:user"]]]);
		expect(rule.verify(attrs)).toBe(true);
	});

	it("fails when scopes are empty", () => {
		const rule = new HasScope("read:user");
		const attrs: Attributes = new Map([["scopes", []]]);
		expect(rule.verify(attrs)).toBe(false);
	});

	it("fails when scopes key is missing", () => {
		const rule = new HasScope("read:user");
		const attrs: Attributes = new Map();
		expect(rule.verify(attrs)).toBe(false);
	});

	it("has ruleType 'scope'", () => {
		const rule = new HasScope("read:user");
		expect(rule.ruleType).toBe("scope");
	});

	it("has code 'invalid_scope'", () => {
		const rule = new HasScope("read:user");
		expect(rule.code).toBe("invalid_scope");
	});
});
