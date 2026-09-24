// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The deprecated `AttrMatchRule`: `AttrPairEqual` under its legacy `ruleType`
 * and message, kept for existing configurations.
 */

import { AttrPairEqual, type AttrPairEqualConfig } from "./AttrPairEqual.mjs";

export type AttrMatchRuleConfig = AttrPairEqualConfig;

/**
 * @deprecated since v0.3 — use {@link AttrPairEqual}.
 *
 * Kept as a thin wrapper that preserves the legacy `ruleType` (`attr_match:{a}:{b}`)
 * and legacy `message` wording. `verify()` semantics are inherited unchanged from
 * `AttrPairEqual`: both named attributes must be non-empty strings and equal.
 * Its config is validated by `super`, so a refusal names `AttrPairEqual`.
 */
export class AttrMatchRule extends AttrPairEqual {
	override readonly ruleType: string;
	override readonly message: string;

	constructor(config: AttrMatchRuleConfig) {
		super(config);
		this.ruleType = config.group ?? `attr_match:${config.a}:${config.b}`;
		this.message = `Attribute constraint not satisfied: ${config.a} and ${config.b} must both be non-empty strings and equal.`;
	}
}
