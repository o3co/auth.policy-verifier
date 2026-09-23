// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `AttrLiteralEqual` rule: an attribute strictly equal to a configured
 * literal.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
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
 *
 * ## Configuration is copied at construction
 *
 * The constructor reads each field of `config` once, validates it, and keeps
 * the validated value in a field of its own; the object is not retained (#255).
 * A caller that mutates the config afterwards changes nothing: the rule answers
 * from the values it validated, and `ruleType` and `message` keep describing
 * them.
 */
export class AttrLiteralEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_not_equal";
	readonly message: string;

	private readonly a: string;
	private readonly v: LiteralValue;

	constructor(config: AttrLiteralEqualConfig) {
		const a = requireAttrName("AttrLiteralEqual", "a", config.a);
		const v = requireLiteralValue("AttrLiteralEqual", "v", config.v);
		const group = requireOptionalGroup("AttrLiteralEqual", config.group);

		this.a = a;
		this.v = v;
		this.ruleType = group ?? `attr_literal_equal:${a}:${typeof v}:${String(v)}`;
		this.message = `Attribute constraint not satisfied: ${a} must equal ${String(v)}.`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const x = attrs.get(this.a);
		if (typeof x !== typeof this.v) return false;
		return x === this.v;
	}
}
