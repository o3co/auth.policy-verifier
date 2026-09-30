// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that reads a delegated token's range into
 * `ATTR_DELEGATION_RANGE`.
 */

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import {
	ATTR_DELEGATION_RANGE,
	DEFAULT_AUTHORIZATION_DETAILS_CLAIM,
	entriesOfType,
	rangePaths,
	resolveRangeType,
} from "../delegation/range.mjs";
import { resolveClaimName } from "./_claims.mjs";

/** Config entry accepted by `DelegationRangeCollector`. */
export interface DelegationRangeCollectorConfig {
	/**
	 * The `authorization_details` type the delegation range is carried under:
	 * the type the issuer's delegation grants write. Required — the same value
	 * `DelegationRangeRuleCollector` is given.
	 */
	type: string;
	/** The claim the entries are read from. Defaults to `authorization_details`. */
	claim?: string;
}

/**
 * Attribute collector that reads the paths of the token's
 * `authorization_details` entries of the configured type into a `string[]`
 * under `ATTR_DELEGATION_RANGE`. A path outside the grammar is left out,
 * which narrows the range; a token with entries of the type but no readable
 * path gets an empty range, which contains nothing. A token with no entry of
 * the type gets no range at all, and `DelegationRangeRuleCollector` then
 * emits no rule for it.
 */
export class DelegationRangeCollector implements AttributeCollector {
	private readonly type: string;
	private readonly claim: string;

	constructor(config: DelegationRangeCollectorConfig) {
		this.type = resolveRangeType("DelegationRangeCollector", config?.type);
		this.claim = resolveClaimName(
			"DelegationRangeCollector",
			config?.claim,
			DEFAULT_AUTHORIZATION_DETAILS_CLAIM,
		);
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		const entries = entriesOfType(context.subject[this.claim], this.type);
		if (entries === null) return new Map();
		return new Map([[ATTR_DELEGATION_RANGE, rangePaths(entries)]]);
	}
}
