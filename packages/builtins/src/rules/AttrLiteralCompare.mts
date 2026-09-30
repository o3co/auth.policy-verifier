// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `AttrLiteralCompare` rule: a numeric attribute compared against a
 * configured number.
 */

import type { ReadonlyAttributes, Rule } from "@o3co/auth.policy-verifier.core";
import {
	applyCompare,
	type CompareOp,
	requireAttrName,
	requireCompareOp,
	requireNumber,
	requireOptionalGroup,
} from "./_sharedValidation.mjs";

export interface AttrLiteralCompareConfig {
	a: string;
	op: CompareOp;
	v: number;
	group?: string;
}

/**
 * Rule that passes when a named attribute is present, is a number, and
 * satisfies the configured comparison operator against the configured literal
 * number `v`. NaN attributes always return false. Missing, null, or non-number
 * attributes return false (safe-deny). NaN is rejected at construction time.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a`, `op`, and `v`:
 *   `attr_literal_compare:{a}:{op}:{String(v)}`
 *
 * Pass an explicit `group` string to override the default ruleType entirely.
 *
 * ## Configuration is copied at construction
 *
 * The constructor validates each field of `config` once and keeps the
 * validated value; the object is not retained, so mutating it afterwards
 * changes neither the rule's answers nor its `ruleType` and `message`.
 */
export class AttrLiteralCompare implements Rule {
	readonly ruleType: string;
	readonly code = "attr_compare_violated";
	readonly message: string;

	private readonly a: string;
	private readonly op: CompareOp;
	private readonly v: number;

	constructor(config: AttrLiteralCompareConfig) {
		const a = requireAttrName("AttrLiteralCompare", "a", config.a);
		const v = requireNumber("AttrLiteralCompare", "v", config.v);
		const op = requireCompareOp("AttrLiteralCompare", config.op);
		const group = requireOptionalGroup("AttrLiteralCompare", config.group);

		this.a = a;
		this.op = op;
		this.v = v;
		this.ruleType = group ?? `attr_literal_compare:${a}:${op}:${String(v)}`;
		this.message = `Attribute constraint not satisfied: ${a} must be ${op} ${String(v)}.`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const x = attrs.get(this.a);
		if (typeof x !== "number") return false;
		return applyCompare(this.op, x, this.v);
	}
}
