// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The rule collector that emits a `WithinDelegationRange` rule for a request
 * made with a delegated token.
 */

import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { resolveClaimName } from "../../collectors/_claims.mjs";
import {
	DEFAULT_AUTHORIZATION_DETAILS_CLAIM,
	entriesOfType,
	resolveRangeType,
} from "../../delegation/range.mjs";
import { WithinDelegationRange } from "../WithinDelegationRange.mjs";

/** Config entry accepted by `DelegationRangeRuleCollector`. */
export interface DelegationRangeRuleCollectorConfig {
	/**
	 * The `authorization_details` type the delegation range is carried under.
	 * Required — the same value `DelegationRangeCollector` is given.
	 */
	type: string;
	/** The claim the entries are read from. Defaults to `authorization_details`. */
	claim?: string;
}

/**
 * Emits one `WithinDelegationRange` rule for the requested path — the raw
 * resource, then the action, joined by `.` — when the token carries an
 * `authorization_details` entry of the configured type, and none otherwise.
 * The rule is a group of its own, so it is decided together with the
 * policies: a delegated token is allowed only what both allow, and a token
 * without a range is decided as it would be without this collector.
 *
 * The range itself is read by `DelegationRangeCollector`, which must be
 * configured with the same `type` and `claim`. Configured apart, the rule is
 * emitted and finds no range, and the request is denied.
 */
export class DelegationRangeRuleCollector implements RuleCollector {
	private readonly type: string;
	private readonly claim: string;

	constructor(config: DelegationRangeRuleCollectorConfig) {
		this.type = resolveRangeType("DelegationRangeRuleCollector", config?.type);
		this.claim = resolveClaimName(
			"DelegationRangeRuleCollector",
			config?.claim,
			DEFAULT_AUTHORIZATION_DETAILS_CLAIM,
		);
	}

	async collect(context: CollectorContext): Promise<Rule[]> {
		if (entriesOfType(context.subject[this.claim], this.type) === null) return [];
		return [new WithinDelegationRange(`${context.resource.raw}.${context.action}`)];
	}
}
