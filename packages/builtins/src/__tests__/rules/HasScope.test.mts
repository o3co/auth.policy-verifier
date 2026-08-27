// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";
import { HasScope } from "#/rules/HasScope.mjs";

const withScopes = (...scopes: unknown[]): Attributes => new Map([["scopes", scopes]]);

describe("HasScope", () => {
	it("passes when scope matches exactly", () => {
		const rule = new HasScope("read:user");
		expect(rule.verify(withScopes("read:user"))).toBe(true);
	});

	it("fails when scope does not match", () => {
		const rule = new HasScope("write:user");
		expect(rule.verify(withScopes("read:user"))).toBe(false);
	});

	it("passes when one of several granted scopes matches", () => {
		const rule = new HasScope("read:user");
		expect(rule.verify(withScopes("write:document", "read:user", "read:project"))).toBe(true);
	});

	it("fails when scopes are empty", () => {
		const rule = new HasScope("read:user");
		expect(rule.verify(withScopes())).toBe(false);
	});

	it("fails when scopes key is missing", () => {
		const rule = new HasScope("read:user");
		expect(rule.verify(new Map())).toBe(false);
	});

	it("has ruleType 'scope'", () => {
		expect(new HasScope("read:user").ruleType).toBe("scope");
	});

	it("has code 'invalid_scope'", () => {
		expect(new HasScope("read:user").code).toBe("invalid_scope");
	});

	// RFC 6749 §3.3 — scope values are case-sensitive, opaque strings. Folding
	// case makes a differently-cased scope satisfy a requirement the issuer never
	// granted, which silently over-grants.
	describe("case sensitivity", () => {
		it("rejects a granted scope that differs only by case", () => {
			const rule = new HasScope("read:project");
			expect(rule.verify(withScopes("read:PROJECT"))).toBe(false);
		});

		it("rejects a granted scope whose action differs only by case", () => {
			const rule = new HasScope("read:project");
			expect(rule.verify(withScopes("READ:project"))).toBe(false);
		});

		it("rejects a required scope that differs only by case from the granted one", () => {
			const rule = new HasScope("READ:User");
			expect(rule.verify(withScopes("read:user"))).toBe(false);
		});

		it("matches a mixed-case scope against an identically-cased requirement", () => {
			const rule = new HasScope("read:Project");
			expect(rule.verify(withScopes("read:Project"))).toBe(true);
		});
	});

	// A scope carrying more than one ":" must never be split down to its first
	// two segments: "read:project:restricted" is a narrower grant than
	// "read:project" and collapsing it treats the narrow one as the broad one.
	describe("multi-colon scopes", () => {
		it("does not let a narrower multi-colon scope satisfy the broader requirement", () => {
			const rule = new HasScope("read:project");
			expect(rule.verify(withScopes("read:project:restricted"))).toBe(false);
		});

		it("does not let a broader scope satisfy a multi-colon requirement", () => {
			const rule = new HasScope("read:project:restricted");
			expect(rule.verify(withScopes("read:project"))).toBe(false);
		});

		it("matches a multi-colon scope against an identical requirement", () => {
			const rule = new HasScope("read:project:restricted");
			expect(rule.verify(withScopes("read:project:restricted"))).toBe(true);
		});

		it("does not match a multi-colon scope against a differently-ordered requirement", () => {
			const rule = new HasScope("read:restricted:project");
			expect(rule.verify(withScopes("read:project:restricted"))).toBe(false);
		});
	});

	describe("bare-scope rewrite (opt-in)", () => {
		it("does not rewrite a bare granted scope by default", () => {
			const rule = new HasScope("read:user");
			expect(rule.verify(withScopes("user"))).toBe(false);
		});

		it("does not rewrite a bare granted scope when explicitly disabled", () => {
			const rule = new HasScope("read:user", { allowBareScopeRewrite: false });
			expect(rule.verify(withScopes("user"))).toBe(false);
		});

		it("rewrites a bare granted scope to read:<scope> when opted in", () => {
			const rule = new HasScope("read:user", { allowBareScopeRewrite: true });
			expect(rule.verify(withScopes("user"))).toBe(true);
		});

		it("only ever rewrites to the read action when opted in", () => {
			const rule = new HasScope("write:user", { allowBareScopeRewrite: true });
			expect(rule.verify(withScopes("user"))).toBe(false);
		});

		it("stays case-sensitive when the rewrite is opted in", () => {
			const rule = new HasScope("read:user", { allowBareScopeRewrite: true });
			expect(rule.verify(withScopes("User"))).toBe(false);
		});

		it("never rewrites a granted scope that already contains a colon", () => {
			// "project:restricted" must not be guessed into "read:project:restricted";
			// which segment is the action is unknowable, and guessing over-grants.
			const rule = new HasScope("read:project:restricted", { allowBareScopeRewrite: true });
			expect(rule.verify(withScopes("project:restricted"))).toBe(false);
		});

		it("still matches exactly when the rewrite is opted in", () => {
			const rule = new HasScope("read:user", { allowBareScopeRewrite: true });
			expect(rule.verify(withScopes("read:user"))).toBe(true);
		});
	});

	// ATTR_SCOPES is written by collectors into an untyped `Attributes` map. A
	// project-side collector that writes a non-string must deny, not throw: a
	// thrown TypeError surfaces as a 500 instead of a decision.
	describe("malformed attribute values", () => {
		it("ignores non-string entries instead of throwing", () => {
			const rule = new HasScope("read:user");
			expect(() => rule.verify(withScopes(42, null, undefined, { s: "read:user" }))).not.toThrow();
			expect(rule.verify(withScopes(42, null, undefined, { s: "read:user" }))).toBe(false);
		});

		it("still finds a matching string among non-string entries", () => {
			const rule = new HasScope("read:user");
			expect(rule.verify(withScopes(42, "read:user"))).toBe(true);
		});
	});
});
