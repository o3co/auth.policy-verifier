// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that splits the OAuth2 `scope` claim (space-delimited)
 * into a `string[]` and exposes it under `ATTR_SCOPES`. Missing or non-string
 * `scope` yields an empty array.
 */
export class PayloadScopeCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const scope = context.payload.scope;
		const scopes = typeof scope === "string" && scope ? scope.split(" ").filter(Boolean) : [];
		return new Map([[ATTR_SCOPES, scopes]]);
	}
}
