// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `AttrLiteralNotEqual` rule: an attribute of the literal's type that is
 * not equal to a configured literal.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
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
 * is performed. If the attribute is missing, null, of the wrong type, or
 * `NaN` the rule returns false (safe-deny). `NaN` is unequal to every number,
 * so `!==` alone would pass it: a restriction that allows on an attribute
 * that is not a number at all (#254). Construction refuses a `NaN` literal
 * for the mirror reason.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a`, `typeof v`, and
 * `String(v)`:
 *   `attr_literal_not_equal:{a}:{typeof v}:{String(v)}`
 *
 * The `typeof v` segment prevents silent `ruleType` collisions between
 * different-type literals that stringify the same way (e.g. `1` vs `"1"`),
 * which would otherwise be OR-combined by the evaluator against the intent
 * of two independent constraints. See AttrLiteralEqual for the same rationale.
 *
 * Pass a shared `group` string to two instances to opt into OR semantics.
 *
 * ## Configuration is copied at construction
 *
 * The constructor reads each field of `config` once, validates it, and keeps
 * the validated value in a field of its own; the object is not retained (#255).
 * A caller that mutates the config afterwards changes nothing: the rule answers
 * from the values it validated, and `ruleType` and `message` keep describing
 * them.
 */
export class AttrLiteralNotEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_equal";
	readonly message: string;

	private readonly a: string;
	private readonly v: LiteralValue;

	constructor(config: AttrLiteralNotEqualConfig) {
		const a = requireAttrName("AttrLiteralNotEqual", "a", config.a);
		const v = requireLiteralValue("AttrLiteralNotEqual", "v", config.v);
		const group = requireOptionalGroup("AttrLiteralNotEqual", config.group);

		this.a = a;
		this.v = v;
		this.ruleType = group ?? `attr_literal_not_equal:${a}:${typeof v}:${String(v)}`;
		this.message = `Attribute constraint not satisfied: ${a} must not equal ${String(v)}.`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const x = attrs.get(this.a);
		if (typeof x !== typeof this.v) return false;
		if (Number.isNaN(x)) return false;
		return x !== this.v;
	}
}
