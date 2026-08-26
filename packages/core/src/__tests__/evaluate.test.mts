// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { evaluate } from "../evaluate.mjs";
import type { Attributes, Rule } from "../types.mjs";

const makeRule = (ruleType: string, code: string, result: boolean): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: (_attrs: Attributes) => result,
});

describe("evaluate", () => {
	it("returns deny when no rules are provided (default-deny)", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, []);
		expect(result).toMatchObject({
			decision: "deny",
			code: "no_applicable_rule",
			message: "No applicable rule was collected for this request",
		});
	});

	it("returns deny when every collector yields no rules for this request", () => {
		// A rule collector may legitimately return [] for a given request shape
		// (e.g. a scope collector facing a scopeless token). The engine must not
		// read "nothing to check" as "nothing to enforce".
		const attrs: Attributes = new Map([["scopes", []]]);
		const result = evaluate(attrs, []);
		expect(result.decision).toBe("deny");
	});

	it("returns allow on an empty rule set only when allow-on-empty is opted into", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [], { onEmptyRuleSet: "allow" });
		expect(result.decision).toBe("allow");
	});

	it("returns deny on an empty rule set when deny-on-empty is stated explicitly", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [], { onEmptyRuleSet: "deny" });
		expect(result.decision).toBe("deny");
	});

	it("returns allow when single rule passes", () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", true)];
		const result = evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when single rule fails", () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", false)];
		const result = evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when any rule in same group passes (OR within group)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", true),
		];
		const result = evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when all rules in a group fail", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", false),
		];
		const result = evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when all groups pass (AND across groups)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", true),
		];
		const result = evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when one group fails (AND across groups)", () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", false),
		];
		const result = evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "no_permission",
			message: "Failed: no_permission",
		});
	});
});

describe("evaluate — structured decision reason (#124)", () => {
	it("reports every group on an allow, naming the rule that satisfied each", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", true),
		]);

		expect(result.reason.groups).toEqual([
			{
				ruleType: "scope",
				passed: true,
				rules: [{ code: "invalid_scope", message: "Failed: invalid_scope", passed: true }],
			},
			{
				ruleType: "permission",
				passed: true,
				rules: [{ code: "no_permission", message: "Failed: no_permission", passed: true }],
			},
		]);
	});

	it("reports which groups passed and which failed on a deny", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", false),
		]);

		expect(result.reason.groups.map((g) => [g.ruleType, g.passed])).toEqual([
			["scope", true],
			["permission", false],
		]);
	});

	it("reports every failing alternative within a failing group", () => {
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "also_invalid", false),
		]);

		const scopeGroup = result.reason.groups.find((g) => g.ruleType === "scope");
		expect(scopeGroup?.passed).toBe(false);
		expect(scopeGroup?.rules.map((r) => r.code)).toEqual(["invalid_scope", "also_invalid"]);
		expect(scopeGroup?.rules.every((r) => !r.passed)).toBe(true);
	});

	it("evaluates later groups even after an earlier one fails", () => {
		// The old evaluator returned on the first failing group, so a deny could
		// not say whether anything after it would also have failed.
		const attrs: Attributes = new Map();
		const result = evaluate(attrs, [
			makeRule("scope", "invalid_scope", false),
			makeRule("permission", "no_permission", false),
		]);

		expect(result.reason.groups).toHaveLength(2);
		expect(result.reason.groups.every((g) => !g.passed)).toBe(true);
		// The deny still names the FIRST failing group, as before.
		expect(result).toMatchObject({ decision: "deny", code: "invalid_scope" });
	});

	it("reports no groups when nothing was collected", () => {
		const result = evaluate(new Map(), []);
		expect(result.reason.groups).toEqual([]);
	});
});
