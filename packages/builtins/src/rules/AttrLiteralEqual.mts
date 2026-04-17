import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	type LiteralValue,
	requireAttrName,
	requireLiteralValue,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrLiteralEqualConfig {
	a: string;
	v: LiteralValue;
	group?: string;
}

/**
 * Rule that passes when a named attribute is present and strictly equal to a
 * configured literal value (string, number, or boolean). No type coercion is
 * performed: the attribute value must be the same type and value as `v`.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a`, `typeof v`, and
 * `String(v)` so that distinct literal requirements are AND-combined by default:
 *   `attr_literal_equal:{a}:{typeof v}:{String(v)}`
 *
 * The `typeof v` segment is required because `String(v)` collapses distinct-
 * type literals that stringify the same way (e.g. `true` vs `"true"`, `1` vs
 * `"1"`). Without it, two rules on the same attribute with different-type
 * literals would share a `ruleType` and be OR-combined by the evaluator,
 * silently weakening authorization.
 *
 * Pass a shared `group` string to two instances to opt into OR semantics
 * (e.g. "role is admin" OR "role is superuser" under one group).
 */
export class AttrLiteralEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_not_equal";
	readonly message: string;

	constructor(private readonly config: AttrLiteralEqualConfig) {
		requireAttrName("AttrLiteralEqual", "a", config.a);
		requireLiteralValue("AttrLiteralEqual", "v", config.v);
		const group = requireOptionalGroup("AttrLiteralEqual", config.group);

		this.ruleType =
			group ?? `attr_literal_equal:${config.a}:${typeof config.v}:${String(config.v)}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must equal ${String(config.v)}.`;
	}

	verify(attrs: Attributes): boolean {
		const x = attrs.get(this.config.a);
		if (typeof x !== typeof this.config.v) return false;
		return x === this.config.v;
	}
}
