// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Decision, Rule } from "./types.mjs";

/**
 * Evaluates collected rules against attributes and returns an allow/deny decision.
 *
 * Semantics: rules are grouped by `ruleType`; each group is evaluated as OR
 * (any rule passing satisfies the group), and all groups must pass (AND across groups)
 * for an allow decision. On deny, the first rule of the failing group supplies
 * the `code` and `message`.
 *
 * @param attrs - Attributes collected for the request (subject, resource, environment).
 * @param rules - Flat list of rules collected from all rule collectors.
 * @returns `{ decision: "allow" }` if every group passes, otherwise a deny decision.
 */
export function evaluate(attrs: Attributes, rules: Rule[]): Decision {
	// Phase 1: group rules by ruleType — rules within a group are alternatives (OR).
	const groups = Map.groupBy(rules, (rule) => rule.ruleType);

	// Phase 2: each group must have at least one passing rule (AND across groups).
	for (const groupRules of groups.values()) {
		const passed = groupRules.some((rule) => rule.verify(attrs));
		if (passed) continue;

		// Deny on the first failing group; representative carries the user-facing reason.
		const representative = groupRules[0];
		return {
			decision: "deny",
			code: representative.code,
			message: representative.message,
		};
	}

	// Phase 3: all groups passed → allow.
	return { decision: "allow" };
}
