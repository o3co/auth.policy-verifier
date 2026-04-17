import {
	AttrLiteralCompare,
	AttrLiteralEqual,
	AttrPairNotEqual,
} from "@o3co/auth.policy-verifier.builtins";
import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import { evaluate } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";

/**
 * Engine-level integration scenario: three rules with distinct default ruleTypes
 * are AND-combined by the evaluator (one group per rule, no shared `group` option).
 *
 * Rules under test:
 *   - AttrLiteralEqual  ({ a: "role",   v: "admin" })   → code "attr_not_equal"
 *   - AttrPairNotEqual  ({ a: "userId", b: "ownerId" }) → code "attr_match"
 *   - AttrLiteralCompare({ a: "level",  v: 5, op: "ge" }) → code "attr_compare_violated"
 *
 * Base attributes (all rules satisfied):
 *   role    = "admin"   (equals literal "admin")
 *   userId  = "u1"      (not equal to ownerId "u2")
 *   ownerId = "u2"
 *   level   = 5         (≥ 5)
 */

describe("evaluate with AttrLiteralEqual + AttrPairNotEqual + AttrLiteralCompare", () => {
	// Rules listed in a fixed order so Scenario C is deterministic.
	// Order: [ruleEqual, rulePairNotEqual, ruleCompare]
	const ruleEqual = new AttrLiteralEqual({ a: "role", v: "admin" });
	const rulePairNotEqual = new AttrPairNotEqual({ a: "userId", b: "ownerId" });
	const ruleCompare = new AttrLiteralCompare({ a: "level", v: 5, op: "ge" });

	const rules: Rule[] = [ruleEqual, rulePairNotEqual, ruleCompare];

	it("Scenario A: all three rules satisfied → allow", () => {
		const attrs: Attributes = new Map([
			["role", "admin"],
			["userId", "u1"],
			["ownerId", "u2"],
			["level", 5],
		]);

		const result = evaluate(attrs, rules);

		expect(result).toEqual({ decision: "allow" });
	});

	it("Scenario B: AttrPairNotEqual fails (userId === ownerId) → deny with attr_match", () => {
		// Break AttrPairNotEqual: userId equals ownerId.
		const attrs: Attributes = new Map([
			["role", "admin"],
			["userId", "u1"],
			["ownerId", "u1"], // same → rule fails
			["level", 5],
		]);

		const result = evaluate(attrs, rules);

		expect(result).toEqual({
			decision: "deny",
			code: rulePairNotEqual.code,
			message: rulePairNotEqual.message,
		});
	});

	it("Scenario C: AttrLiteralEqual and AttrPairNotEqual both fail → deny with first failing group (attr_not_equal)", () => {
		// Break AttrLiteralEqual: role is not "admin".
		// Break AttrPairNotEqual: userId equals ownerId.
		// AttrLiteralCompare still passes.
		// Evaluator processes groups in insertion order: ruleEqual's group is first,
		// so the deny reflects ruleEqual's code/message.
		const attrs: Attributes = new Map([
			["role", "user"], // not "admin" → AttrLiteralEqual fails
			["userId", "u1"],
			["ownerId", "u1"], // same → AttrPairNotEqual fails
			["level", 5],
		]);

		const result = evaluate(attrs, rules);

		expect(result).toEqual({
			decision: "deny",
			code: ruleEqual.code,
			message: ruleEqual.message,
		});
	});
});
