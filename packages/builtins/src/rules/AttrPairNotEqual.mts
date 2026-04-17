import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	requireAttrName,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrPairNotEqualConfig {
	a: string;
	b: string;
	group?: string;
}

/**
 * Rule that passes when two named attributes are present, are non-empty
 * strings, and are strictly NOT equal. No type coercion is performed: both
 * attribute values must be non-empty strings. Missing, null, empty, or
 * non-string attributes return false (safe-deny).
 *
 * ## Denial code
 *
 * The denial code is "attr_match": the rule failed because the pair matched
 * when it was required to differ.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a` and `b`:
 *   `attr_pair_not_equal:{a}:{b}`
 *
 * Pass a shared `group` string to two instances to opt into OR semantics.
 */
export class AttrPairNotEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_match";
	readonly message: string;

	constructor(private readonly config: AttrPairNotEqualConfig) {
		requireAttrName("AttrPairNotEqual", "a", config.a);
		requireAttrName("AttrPairNotEqual", "b", config.b);
		const group = requireOptionalGroup("AttrPairNotEqual", config.group);

		this.ruleType = group ?? `attr_pair_not_equal:${config.a}:${config.b}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must not equal ${config.b}.`;
	}

	verify(attrs: Attributes): boolean {
		const a = attrs.get(this.config.a);
		const b = attrs.get(this.config.b);
		if (typeof a !== "string" || a.length === 0) return false;
		if (typeof b !== "string" || b.length === 0) return false;
		return a !== b;
	}
}
