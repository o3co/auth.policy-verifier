// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { evaluate } from "../evaluate.mjs";
import { FailureRecord } from "../failureSource.mjs";
import {
	type AnyRule,
	type AsyncRule,
	type Attributes,
	isRestrictingRule,
	type Rule,
} from "../types.mjs";

const makeRule = (ruleType: string, code: string, result: boolean): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: (_attrs: Attributes) => result,
});

describe("evaluate", () => {
	it("returns deny when no rules are provided (default-deny)", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, []);
		expect(result).toMatchObject({
			decision: "deny",
			code: "no_applicable_rule",
			message: "No applicable rule was collected for this request",
		});
	});

	it("returns deny when every collector yields no rules for this request", async () => {
		// A rule collector may legitimately return [] for a given request shape
		// (e.g. a scope collector facing a scopeless token). The engine must not
		// read "nothing to check" as "nothing to enforce".
		const attrs: Attributes = new Map([["scopes", []]]);
		const result = await evaluate(attrs, []);
		expect(result.decision).toBe("deny");
	});

	it("returns allow on an empty rule set only when allow-on-empty is opted into", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [], { onEmptyRuleSet: "allow" });
		expect(result.decision).toBe("allow");
	});

	it("returns deny on an empty rule set when deny-on-empty is stated explicitly", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [], { onEmptyRuleSet: "deny" });
		expect(result.decision).toBe("deny");
	});

	it("returns allow when single rule passes", async () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", true)];
		const result = await evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when single rule fails", async () => {
		const attrs: Attributes = new Map();
		const rules = [makeRule("scope", "invalid_scope", false)];
		const result = await evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when any rule in same group passes (OR within group)", async () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", true),
		];
		const result = await evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when all rules in a group fail", async () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "invalid_scope", false),
		];
		const result = await evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "invalid_scope",
			message: "Failed: invalid_scope",
		});
	});

	it("returns allow when all groups pass (AND across groups)", async () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", true),
		];
		const result = await evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
	});

	it("returns deny when one group fails (AND across groups)", async () => {
		const attrs: Attributes = new Map();
		const rules = [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", false),
		];
		const result = await evaluate(attrs, rules);
		expect(result).toMatchObject({
			decision: "deny",
			code: "no_permission",
			message: "Failed: no_permission",
		});
	});
});

describe("evaluate — structured decision reason", () => {
	it("reports every group on an allow, naming the rule that satisfied each", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", true),
		]);

		expect(result.reason.groups).toEqual([
			{
				ruleType: "scope",
				passed: true,
				evaluated: [{ code: "invalid_scope", message: "Failed: invalid_scope", passed: true }],
				satisfiedBy: { code: "invalid_scope", message: "Failed: invalid_scope", passed: true },
			},
			{
				ruleType: "permission",
				passed: true,
				evaluated: [{ code: "no_permission", message: "Failed: no_permission", passed: true }],
				satisfiedBy: { code: "no_permission", message: "Failed: no_permission", passed: true },
			},
		]);
	});

	it("reports which groups passed and which failed on a deny", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "invalid_scope", true),
			makeRule("permission", "no_permission", false),
		]);

		expect(result.reason.groups.map((g) => [g.ruleType, g.passed])).toEqual([
			["scope", true],
			["permission", false],
		]);
	});

	it("reports every failing alternative within a failing group", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "invalid_scope", false),
			makeRule("scope", "also_invalid", false),
		]);

		const scopeGroup = result.reason.groups.find((g) => g.ruleType === "scope");
		expect(scopeGroup?.passed).toBe(false);
		expect(scopeGroup?.evaluated.map((r) => r.code)).toEqual(["invalid_scope", "also_invalid"]);
		expect(scopeGroup?.evaluated.every((r) => !r.passed)).toBe(true);
	});

	it("evaluates later groups even after an earlier one fails", async () => {
		// Every group runs, so a deny can say whether a later group would also
		// have failed.
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "invalid_scope", false),
			makeRule("permission", "no_permission", false),
		]);

		expect(result.reason.groups).toHaveLength(2);
		expect(result.reason.groups.every((g) => !g.passed)).toBe(true);
		// The deny names the first failing group.
		expect(result).toMatchObject({ decision: "deny", code: "invalid_scope" });
	});

	it("reports no groups when nothing was collected", async () => {
		const result = await evaluate(new Map(), []);
		expect(result.reason.groups).toEqual([]);
	});
});

describe("evaluate — RuleGroupOutcome.evaluated means what ran", () => {
	it("on a pass, evaluated lists the tried-and-failed alternatives before the passing rule", async () => {
		// `evaluated` lists every rule that ran, the failed attempts included, so
		// a consumer counting "rules evaluated" counts them too.
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "first_failed", false),
			makeRule("scope", "second_failed", false),
			makeRule("scope", "finally_passed", true),
		]);

		expect(result.decision).toBe("allow");
		const group = result.reason.groups[0];
		expect(group.passed).toBe(true);
		expect(group.evaluated.map((r) => [r.code, r.passed])).toEqual([
			["first_failed", false],
			["second_failed", false],
			["finally_passed", true],
		]);
	});

	it("on a pass, satisfiedBy names the deciding rule and matches the last evaluated entry", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "first_failed", false),
			makeRule("scope", "finally_passed", true),
		]);

		const group = result.reason.groups[0];
		expect(group.passed).toBe(true);
		if (!group.passed) throw new Error("unreachable — narrows the union");
		expect(group.satisfiedBy).toEqual({
			code: "finally_passed",
			message: "Failed: finally_passed",
			passed: true,
		});
		expect(group.satisfiedBy).toEqual(group.evaluated.at(-1));
	});

	it("on a pass, alternatives after the passing rule never run and are not reported", async () => {
		const attrs: Attributes = new Map();
		let laterAlternativeRan = false;
		const neverReached: Rule = {
			ruleType: "scope",
			code: "never_reached",
			message: "Failed: never_reached",
			verify: () => {
				laterAlternativeRan = true;
				return true;
			},
		};
		const result = await evaluate(attrs, [makeRule("scope", "finally_passed", true), neverReached]);

		const group = result.reason.groups[0];
		expect(laterAlternativeRan).toBe(false);
		expect(group.evaluated.map((r) => r.code)).toEqual(["finally_passed"]);
	});

	it("on a fail, evaluated lists every alternative and satisfiedBy is absent", async () => {
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "first_failed", false),
			makeRule("scope", "second_failed", false),
		]);

		expect(result.decision).toBe("deny");
		const group = result.reason.groups[0];
		expect(group.passed).toBe(false);
		expect(group.evaluated.map((r) => [r.code, r.passed])).toEqual([
			["first_failed", false],
			["second_failed", false],
		]);
		expect("satisfiedBy" in group).toBe(false);
	});

	it("still takes the deny code from the first alternative of the first failing group", async () => {
		// The deny's representative rule is `evaluated[0]`: a failing group ran
		// all its alternatives in order.
		const attrs: Attributes = new Map();
		const result = await evaluate(attrs, [
			makeRule("scope", "first_failed", false),
			makeRule("scope", "second_failed", false),
		]);

		expect(result).toMatchObject({ decision: "deny", code: "first_failed" });
	});
});

/*
 * A restricting rule narrows what the granting rules allow and is never a
 * reason to allow on its own: a request that only restricting rules apply to
 * has no applicable rule, whatever they answer.
 */
describe("evaluate — restricting rules", () => {
	const restricting = (ruleType: string, code: string, result: boolean): Rule => ({
		...makeRule(ruleType, code, result),
		restricts: true,
	});

	it("denies a request only restricting rules apply to, without asking them", async () => {
		const verify = vi.fn(() => true);
		const rules: Rule[] = [{ ...restricting("range", "outside_range", true), verify }];

		const result = await evaluate(new Map(), rules);

		expect(result).toEqual({
			decision: "deny",
			code: "no_applicable_rule",
			message: "No applicable rule was collected for this request",
			reason: { groups: [] },
		});
		expect(verify).not.toHaveBeenCalled();
	});

	it("still holds such a request to its restrictions under onEmptyRuleSet allow", async () => {
		const passing = await evaluate(new Map(), [restricting("range", "outside_range", true)], {
			onEmptyRuleSet: "allow",
		});
		expect(passing.decision).toBe("allow");
		expect(passing.reason.groups.map((group) => group.ruleType)).toEqual(["range"]);

		const failing = await evaluate(new Map(), [restricting("range", "outside_range", false)], {
			onEmptyRuleSet: "allow",
		});
		expect(failing).toMatchObject({ decision: "deny", code: "outside_range" });
	});

	it.each([
		[true, true, "allow", undefined],
		[true, false, "deny", "outside_range"],
		[false, true, "deny", "invalid_scope"],
	] as const)(
		"decides a granting group (%s) and a restricting group (%s) together: %s",
		async (grants, within, decision, code) => {
			const result = await evaluate(new Map(), [
				makeRule("scope", "invalid_scope", grants),
				restricting("range", "outside_range", within),
			]);

			expect(result.decision).toBe(decision);
			if (code !== undefined) expect(result).toMatchObject({ code });
		},
	);

	it("refuses a group that mixes restricting and granting rules, before any rule runs", async () => {
		// A group is an OR: a restricting alternative that passed would satisfy
		// the group in place of the grant that failed.
		const verify = vi.fn(() => false);
		const rules: Rule[] = [
			{ ...makeRule("scope", "invalid_scope", false), verify },
			restricting("scope", "outside_range", true),
		];

		const failures = new FailureRecord();
		const error = await evaluate(new Map(), rules, { failures }).catch((cause: unknown) => cause);

		expect(error).toBeInstanceOf(TypeError);
		expect(verify).not.toHaveBeenCalled();
		// The group is named by the failure source, which the server checks
		// before it logs a ruleType, and not by the message, which it logs as is.
		expect(failures.sourceOf(error)).toEqual({
			kind: "rule",
			ruleType: "scope",
			code: "invalid_scope",
		});
		expect((error as Error).message).not.toContain("scope");
	});

	it("names the refused group by the ruleType it was grouped under, read once", async () => {
		let reads = 0;
		const granting = makeRule("scope", "invalid_scope", false);
		Object.defineProperty(granting, "ruleType", {
			get() {
				reads += 1;
				return reads === 1 ? "scope" : "elsewhere";
			},
		});
		const failures = new FailureRecord();

		const error = await evaluate(
			new Map(),
			[granting, restricting("scope", "outside_range", true)],
			{
				failures,
			},
		).catch((cause: unknown) => cause);

		expect(failures.sourceOf(error)).toMatchObject({ kind: "rule", ruleType: "scope" });
	});

	it("reads each rule's marker once, so a rule cannot be restricting to one check and granting to the next", async () => {
		let reads = 0;
		const rule = makeRule("range", "outside_range", true);
		Object.defineProperty(rule, "restricts", {
			get() {
				reads += 1;
				return reads === 1 ? true : undefined;
			},
		});

		const result = await evaluate(new Map(), [rule]);

		expect(result).toMatchObject({ decision: "deny", code: "no_applicable_rule" });
		expect(reads).toBe(1);
	});

	it("names the strict reading isRestrictingRule", () => {
		expect(isRestrictingRule(restricting("range", "outside_range", true))).toBe(true);
		expect(isRestrictingRule(makeRule("scope", "invalid_scope", true))).toBe(false);
		expect(
			isRestrictingRule({
				...makeRule("scope", "invalid_scope", true),
				restricts: 1,
			} as unknown as Rule),
		).toBe(false);
	});

	it("reads only `restricts: true` as restricting", async () => {
		// The same strict discriminant as `async: true`: anything else is the
		// granting rule every rule was before.
		const rule = {
			...makeRule("scope", "invalid_scope", true),
			restricts: "yes",
		} as unknown as Rule;

		expect((await evaluate(new Map(), [rule])).decision).toBe("allow");
	});

	it("treats an asynchronous restricting rule as it treats a synchronous one", async () => {
		const decide = vi.fn(async () => true);
		const rule: AsyncRule = {
			ruleType: "range",
			code: "outside_range",
			message: "Failed: outside_range",
			async: true,
			restricts: true,
			decide,
		};

		const alone = await evaluate(new Map(), [rule]);
		expect(alone).toMatchObject({ decision: "deny", code: "no_applicable_rule" });
		expect(decide).not.toHaveBeenCalled();

		const beside: AnyRule[] = [makeRule("scope", "invalid_scope", true), rule];
		expect((await evaluate(new Map(), beside)).decision).toBe("allow");
		expect(decide).toHaveBeenCalledTimes(1);
	});
});
