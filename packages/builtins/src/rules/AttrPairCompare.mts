import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	applyCompare,
	type CompareOp,
	requireAttrName,
	requireCompareOp,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrPairCompareConfig {
	a: string;
	op: CompareOp;
	b: string;
	group?: string;
}

/**
 * Rule that passes when two named attributes are present, are both numbers,
 * and satisfy the configured comparison operator. NaN on either side always
 * returns false (JS native comparison semantics). Missing, null, or non-number
 * attributes return false (safe-deny).
 *
 * Unlike AttrLiteralCompare, the right-hand side comes from the attributes map
 * at evaluation time rather than from a static config value — so NaN is not
 * rejected at construction time.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a`, `op`, and `b`:
 *   `attr_pair_compare:{a}:{op}:{b}`
 *
 * Pass an explicit `group` string to override the default ruleType entirely.
 */
export class AttrPairCompare implements Rule {
	readonly ruleType: string;
	readonly code = "attr_compare_violated";
	readonly message: string;

	constructor(private readonly config: AttrPairCompareConfig) {
		requireAttrName("AttrPairCompare", "a", config.a);
		requireAttrName("AttrPairCompare", "b", config.b);
		requireCompareOp("AttrPairCompare", config.op);
		const group = requireOptionalGroup("AttrPairCompare", config.group);

		this.ruleType = group ?? `attr_pair_compare:${config.a}:${config.op}:${config.b}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must be ${config.op} ${config.b}.`;
	}

	verify(attrs: Attributes): boolean {
		const a = attrs.get(this.config.a);
		const b = attrs.get(this.config.b);
		if (typeof a !== "number") return false;
		if (typeof b !== "number") return false;
		return applyCompare(this.config.op, a, b);
	}
}
