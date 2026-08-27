// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Decision, Rule, RuleGroupOutcome, RuleOutcome } from "./types.mjs";

/** Deny returned when no rule group applied to the request. */
const NO_APPLICABLE_RULE: Omit<Decision & { decision: "deny" }, "reason"> = {
	decision: "deny",
	code: "no_applicable_rule",
	message: "No applicable rule was collected for this request",
};

/** Options controlling evaluator semantics that a deployment may override. */
export interface EvaluateOptions {
	/**
	 * Decision returned when the rule set is empty — no collector produced a rule
	 * for this request. Defaults to `"deny"`.
	 *
	 * `"allow"` is an explicit, per-deployment opt-out of default-deny and turns
	 * the engine fail-open: any request that collects no rules is permitted. Only
	 * set it for a pipeline whose authorization is enforced elsewhere.
	 */
	onEmptyRuleSet?: "deny" | "allow";
}

/**
 * Evaluates collected rules against attributes and returns an allow/deny decision.
 *
 * Semantics: rules are grouped by `ruleType`; each group is evaluated as OR
 * (any rule passing satisfies the group), and all groups must pass (AND across groups)
 * for an allow decision. On deny, the first rule of the failing group supplies
 * the `code` and `message`.
 *
 * Every decision carries a structured `reason` naming each rule group and how it
 * came out, so a caller can answer "why" without re-running the pipeline.
 *
 * An empty rule set is **denied by default**: "no rule applied" means the request
 * was never authorized, not that it needs no authorization. This matches the
 * implicit-deny semantics of OPA / OpenFGA / Cedar, so an engine swapped in behind
 * the same decision contract does not change the outcome. `onEmptyRuleSet: "allow"`
 * opts a deployment out of it.
 *
 * @param attrs - Attributes collected for the request (subject, resource, environment).
 * @param rules - Flat list of rules collected from all rule collectors.
 * @param options - Optional evaluator semantics overrides.
 * @returns `{ decision: "allow" }` if every group passes, otherwise a deny decision.
 */
export function evaluate(attrs: Attributes, rules: Rule[], options?: EvaluateOptions): Decision {
	// Phase 1: group rules by ruleType — rules within a group are alternatives (OR).
	const groups = Map.groupBy(rules, (rule) => rule.ruleType);

	// Phase 2: nothing to evaluate → default-deny unless the deployment opted out.
	if (groups.size === 0) {
		const reason = { groups: [] };
		return options?.onEmptyRuleSet === "allow"
			? { decision: "allow", reason }
			: { ...NO_APPLICABLE_RULE, reason };
	}

	// Phase 3: each group must have at least one passing rule (AND across groups).
	// Every group is evaluated, including groups after the first failing one:
	// stopping early cannot report which of the remaining groups would also have
	// failed, which is the question a deny explanation exists to answer. Rules are
	// pure predicates over attributes by contract, so running them all is safe.
	const outcomes: RuleGroupOutcome[] = [];
	for (const [ruleType, groupRules] of groups) {
		outcomes.push(evaluateGroup(ruleType, groupRules, attrs));
	}

	// Phase 4: deny names the FIRST failing group, as before; reason carries all.
	const reason = { groups: outcomes };
	const firstFailure = outcomes.find((group) => !group.passed);
	if (firstFailure) {
		const representative = firstFailure.evaluated[0];
		return {
			decision: "deny",
			code: representative.code,
			message: representative.message,
			reason,
		};
	}

	return { decision: "allow", reason };
}

/**
 * Evaluates one `ruleType` group. The group is an OR, so evaluation stops at
 * the first passing rule. `evaluated` reports exactly the rules that ran, in
 * order — on a pass that is every tried-and-failed alternative followed by the
 * passing rule (named again as `satisfiedBy`); on a fail, every alternative.
 */
function evaluateGroup(ruleType: string, rules: Rule[], attrs: Attributes): RuleGroupOutcome {
	const evaluated: RuleOutcome[] = [];
	for (const rule of rules) {
		const passed = rule.verify(attrs);
		const outcome = { code: rule.code, message: rule.message, passed };
		evaluated.push(outcome);
		if (passed) return { ruleType, passed: true, evaluated, satisfiedBy: outcome };
	}
	return { ruleType, passed: false, evaluated };
}
