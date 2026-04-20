// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
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
 */
export class AttrLiteralCompare implements Rule {
	readonly ruleType: string;
	readonly code = "attr_compare_violated";
	readonly message: string;

	constructor(private readonly config: AttrLiteralCompareConfig) {
		requireAttrName("AttrLiteralCompare", "a", config.a);
		requireNumber("AttrLiteralCompare", "v", config.v);
		requireCompareOp("AttrLiteralCompare", config.op);
		const group = requireOptionalGroup("AttrLiteralCompare", config.group);

		this.ruleType = group ?? `attr_literal_compare:${config.a}:${config.op}:${String(config.v)}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must be ${config.op} ${String(config.v)}.`;
	}

	verify(attrs: Attributes): boolean {
		const x = attrs.get(this.config.a);
		if (typeof x !== "number") return false;
		return applyCompare(this.config.op, x, this.config.v);
	}
}
