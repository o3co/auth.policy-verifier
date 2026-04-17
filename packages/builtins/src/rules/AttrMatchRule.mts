import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";

export interface AttrMatchRuleConfig {
	a: string;
	b: string;
	/**
	 * Optional grouping key used as `ruleType`. See the class comment for
	 * how this interacts with the evaluator's OR-within-group /
	 * AND-across-groups semantics.
	 */
	group?: string;
}

/**
 * Rule that passes when two named attributes are present, are non-empty
 * strings, and are equal. A pure predicate over the attributes map —
 * `verify(attrs)` does not touch `CollectorContext` and does not close
 * over request state.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. If every `AttrMatchRule` shared one fixed `ruleType`,
 * two instances collected for different comparisons (e.g. subject vs.
 * subscriber AND tenant vs. request-tenant) would be OR'd together and
 * authorization would weaken silently.
 *
 * To default to the safe reading of "each distinct pair of attributes
 * is a separate AND-combined requirement", `ruleType` is derived from
 * `a` and `b` when `group` is not given: `attr_match:{a}:{b}`.
 *
 * When callers actually want two comparisons to be OR-combined
 * (alternative identities, for example), they opt in explicitly by
 * passing the same `group` to both rule instances.
 */
export class AttrMatchRule implements Rule {
	readonly ruleType: string;
	readonly code = "attr_mismatch";
	readonly message: string;

	constructor(private readonly config: AttrMatchRuleConfig) {
		this.ruleType = config.group ?? `attr_match:${config.a}:${config.b}`;
		this.message = `Attribute constraint not satisfied: ${config.a} and ${config.b} must both be non-empty strings and equal.`;
	}

	verify(attrs: Attributes): boolean {
		const a = attrs.get(this.config.a);
		const b = attrs.get(this.config.b);
		if (typeof a !== "string" || a.length === 0) return false;
		if (typeof b !== "string" || b.length === 0) return false;
		return a === b;
	}
}
