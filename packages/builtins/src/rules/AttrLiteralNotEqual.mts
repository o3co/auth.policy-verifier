import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	type LiteralValue,
	requireAttrName,
	requireLiteralValue,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrLiteralNotEqualConfig {
	a: string;
	v: LiteralValue;
	group?: string;
}

/**
 * Rule that passes when a named attribute is present, matches the type of the
 * configured literal value, and is strictly NOT equal to it. No type coercion
 * is performed. If the attribute is missing, null, or of the wrong type the
 * rule returns false (safe-deny).
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a` and `v`:
 *   `attr_literal_not_equal:{a}:{String(v)}`
 *
 * Pass a shared `group` string to two instances to opt into OR semantics.
 */
export class AttrLiteralNotEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_equal";
	readonly message: string;

	constructor(private readonly config: AttrLiteralNotEqualConfig) {
		requireAttrName("AttrLiteralNotEqual", "a", config.a);
		requireLiteralValue("AttrLiteralNotEqual", "v", config.v);
		const group = requireOptionalGroup("AttrLiteralNotEqual", config.group);

		this.ruleType = group ?? `attr_literal_not_equal:${config.a}:${String(config.v)}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must not equal ${String(config.v)}.`;
	}

	verify(attrs: Attributes): boolean {
		const x = attrs.get(this.config.a);
		if (typeof x !== typeof this.config.v) return false;
		return x !== this.config.v;
	}
}
