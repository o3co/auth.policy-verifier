// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `AttrLiteralNotIn` rule: an attribute of the values' type that is none of
 * a configured set of literals.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	computeValuesKey,
	type LiteralValue,
	requireAttrName,
	requireHomogeneousLiteralArray,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrLiteralNotInConfig {
	a: string;
	values: LiteralValue[];
	group?: string;
}

/**
 * Rule that passes when a named attribute is present, matches the element type
 * of the configured values array, and is NOT included in that array. No type
 * coercion is performed. If the attribute is missing, null, of the wrong
 * type, or `NaN` the rule returns false (safe-deny). `NaN` is in no set of
 * numbers — construction refuses one that holds it — so the membership test
 * alone would pass it: a restriction that allows on an attribute that is not
 * a number at all (#254).
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a` and a stable
 * content-hash key over the values array:
 *   `attr_literal_not_in:{a}:{valuesKey}`
 *
 * Pass an explicit `group` string to override the default ruleType entirely.
 *
 * ## Configuration is copied at construction
 *
 * The constructor reads each field of `config` once, validates it, and keeps
 * the validated value in a field of its own; the object is not retained (#255).
 * A caller that mutates the config afterwards changes nothing: the rule answers
 * from the values it validated, and `ruleType` and `message` keep describing
 * them.
 */
export class AttrLiteralNotIn implements Rule {
	readonly ruleType: string;
	readonly code = "attr_in_set";
	readonly message: string;

	private readonly a: string;
	private readonly elementType: string;
	private readonly valuesSet: Set<LiteralValue>;

	constructor(config: AttrLiteralNotInConfig) {
		const a = requireAttrName("AttrLiteralNotIn", "a", config.a);
		const values = requireHomogeneousLiteralArray("AttrLiteralNotIn", config.values);
		const group = requireOptionalGroup("AttrLiteralNotIn", config.group);

		this.a = a;
		this.elementType = typeof values[0];
		this.valuesSet = new Set(values);

		const valuesKey = computeValuesKey(values);
		this.ruleType = group ?? `attr_literal_not_in:${a}:${valuesKey}`;
		this.message = `Attribute constraint not satisfied: ${a} must not be one of [${values.map(String).join(", ")}].`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const x = attrs.get(this.a);
		if (typeof x !== this.elementType) return false;
		if (Number.isNaN(x)) return false;
		return !this.valuesSet.has(x as LiteralValue);
	}
}
