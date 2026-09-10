// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";
import { DEFAULT_SCOPE_CLAIM, resolveClaimName, scopesFrom } from "./_claims.mjs";

/** Config entry accepted by `PayloadScopeCollector`. */
export interface PayloadScopeCollectorConfig {
	/**
	 * The claim the scopes are read from (#219). Defaults to `scope`, the
	 * space-delimited OAuth claim; `scp` for Okta, `permissions` for Auth0,
	 * both of which are arrays of strings. Either shape is read.
	 */
	claim?: string;
}

/**
 * Attribute collector that reads the scope claim — a space-delimited string
 * or an array of strings — into a `string[]` under `ATTR_SCOPES`. Missing or
 * malformed yields an empty array, and so does a list carrying a non-string:
 * a value that is not a scope list asserts no capability.
 */
export class PayloadScopeCollector implements AttributeCollector {
	private readonly claim: string;

	constructor(config?: PayloadScopeCollectorConfig) {
		this.claim = resolveClaimName("PayloadScopeCollector", config?.claim, DEFAULT_SCOPE_CLAIM);
	}

	async collect(context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_SCOPES, scopesFrom(context.subject[this.claim])]]);
	}
}
