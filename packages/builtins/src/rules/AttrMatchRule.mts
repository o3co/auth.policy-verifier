import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";

export interface AttrMatchRuleConfig {
	a: string;
	b: string;
}

/**
 * Rule that passes when two named attributes are present, are non-empty
 * strings, and are equal. A pure predicate over the attributes map —
 * callers provide both attribute keys via configuration, and the rule
 * neither reads nor closes over `CollectorContext`.
 *
 * Typical use: a consuming project's `RuleCollector` collects the two
 * values to compare through its own `AttributeCollector`s (for example,
 * a JWT-subject collector and a request-context-field collector) and
 * produces an `AttrMatchRule` parameterised with their keys.
 */
export class AttrMatchRule implements Rule {
	readonly ruleType = "attr_match";
	readonly code = "attr_mismatch";
	readonly message: string;

	constructor(private readonly config: AttrMatchRuleConfig) {
		this.message = `attributes ${config.a} and ${config.b} do not match`;
	}

	verify(attrs: Attributes): boolean {
		const a = attrs.get(this.config.a);
		const b = attrs.get(this.config.b);
		return typeof a === "string" && a.length > 0 && typeof b === "string" && a === b;
	}
}
