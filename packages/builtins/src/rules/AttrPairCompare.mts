// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `AttrPairCompare` rule: two numeric attributes compared with each other.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
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
 *
 * ## Configuration is copied at construction
 *
 * The constructor reads each field of `config` once, validates it, and keeps
 * the validated value in a field of its own; the object is not retained (#255).
 * A caller that mutates the config afterwards changes nothing: the rule answers
 * from the values it validated, and `ruleType` and `message` keep describing
 * them.
 */
export class AttrPairCompare implements Rule {
	readonly ruleType: string;
	readonly code = "attr_compare_violated";
	readonly message: string;

	private readonly a: string;
	private readonly op: CompareOp;
	private readonly b: string;

	constructor(config: AttrPairCompareConfig) {
		const a = requireAttrName("AttrPairCompare", "a", config.a);
		const b = requireAttrName("AttrPairCompare", "b", config.b);
		const op = requireCompareOp("AttrPairCompare", config.op);
		const group = requireOptionalGroup("AttrPairCompare", config.group);

		this.a = a;
		this.op = op;
		this.b = b;
		this.ruleType = group ?? `attr_pair_compare:${a}:${op}:${b}`;
		this.message = `Attribute constraint not satisfied: ${a} must be ${op} ${b}.`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const a = attrs.get(this.a);
		const b = attrs.get(this.b);
		if (typeof a !== "number") return false;
		if (typeof b !== "number") return false;
		return applyCompare(this.op, a, b);
	}
}
