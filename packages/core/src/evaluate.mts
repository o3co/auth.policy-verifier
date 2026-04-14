import type { Attributes, Decision, Rule } from "./types.mjs";

export function evaluate(attrs: Attributes, rules: Rule[]): Decision {
	const groups = new Map<string, Rule[]>();
	for (const rule of rules) {
		const group = groups.get(rule.ruleType);
		if (group) {
			group.push(rule);
		} else {
			groups.set(rule.ruleType, [rule]);
		}
	}

	for (const groupRules of groups.values()) {
		const passed = groupRules.some((rule) => rule.verify(attrs));
		if (!passed) {
			const representative = groupRules[0];
			return {
				decision: "deny",
				code: representative.code,
				message: representative.message,
			};
		}
	}

	return { decision: "allow" };
}
