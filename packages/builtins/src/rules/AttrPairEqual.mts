// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import { requireAttrName, requireOptionalGroup } from "./_sharedValidation.mjs";

export interface AttrPairEqualConfig {
	a: string;
	b: string;
	group?: string;
}

/**
 * Rule that passes when two named attributes are present, are non-empty
 * strings, and are strictly equal. No type coercion is performed: both
 * attribute values must be non-empty strings.
 *
 * ## Backward compatibility
 *
 * AttrPairEqual deliberately retains the string-only semantic of the legacy
 * AttrMatchRule. Do not widen verify() to accept numbers or booleans — the
 * Phase 4 AttrMatchRule alias depends on this invariant.
 *
 * ## Grouping and the default ruleType
 *
 * The evaluator groups rules by `ruleType`, ORs within a group, and ANDs
 * across groups. The default `ruleType` is derived from `a` and `b` so that
 * distinct pair requirements are AND-combined by default:
 *   `attr_pair_equal:{a}:{b}`
 *
 * Pass a shared `group` string to two instances to opt into OR semantics.
 */
export class AttrPairEqual implements Rule {
	readonly ruleType: string;
	readonly code = "attr_mismatch";
	readonly message: string;

	constructor(private readonly config: AttrPairEqualConfig) {
		requireAttrName("AttrPairEqual", "a", config.a);
		requireAttrName("AttrPairEqual", "b", config.b);
		const group = requireOptionalGroup("AttrPairEqual", config.group);

		this.ruleType = group ?? `attr_pair_equal:${config.a}:${config.b}`;
		this.message = `Attribute constraint not satisfied: ${config.a} must equal ${config.b}.`;
	}

	verify(attrs: Attributes): boolean {
		const a = attrs.get(this.config.a);
		const b = attrs.get(this.config.b);
		if (typeof a !== "string" || a.length === 0) return false;
		if (typeof b !== "string" || b.length === 0) return false;
		return a === b;
	}
}
