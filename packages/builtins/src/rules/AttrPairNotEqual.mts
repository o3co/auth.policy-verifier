// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
import { requireAttrName, requireOptionalGroup } from "./_sharedValidation.mjs";

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
 *
 * ## Configuration is copied at construction
 *
 * The constructor reads each field of `config` once, validates it, and keeps
 * the validated value in a field of its own; the object is not retained (#255).
 * A caller that mutates the config afterwards changes nothing: the rule answers
 * from the values it validated, and `ruleType` and `message` keep describing
 * them.
 */
export class AttrPairNotEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_match";
	readonly message: string;

	private readonly a: string;
	private readonly b: string;

	constructor(config: AttrPairNotEqualConfig) {
		const a = requireAttrName("AttrPairNotEqual", "a", config.a);
		const b = requireAttrName("AttrPairNotEqual", "b", config.b);
		const group = requireOptionalGroup("AttrPairNotEqual", config.group);

		this.a = a;
		this.b = b;
		this.ruleType = group ?? `attr_pair_not_equal:${a}:${b}`;
		this.message = `Attribute constraint not satisfied: ${a} must not equal ${b}.`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const a = attrs.get(this.a);
		const b = attrs.get(this.b);
		if (typeof a !== "string" || a.length === 0) return false;
		if (typeof b !== "string" || b.length === 0) return false;
		return a !== b;
	}
}
