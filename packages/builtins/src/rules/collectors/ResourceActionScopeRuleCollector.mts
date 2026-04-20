// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasScope } from "../HasScope.mjs";

/**
 * Generates a HasScope rule derived from the request action and resource type.
 *
 * ## Scope as capability ceiling
 *
 * The JWT `scope` claim represents what the session **can request** — a
 * capability ceiling — not what the session **has been granted**. Whether the
 * operation is ultimately permitted is determined by the full rule pipeline
 * (other collectors, resource-owner policy, etc.). This collector enforces the
 * ceiling only: it produces a `HasScope` rule for the requested
 * `{action}:{resourceType}`, which must be satisfied by the token's scopes.
 *
 * ## Behavior for scopeless tokens
 *
 * Flows where the IdP does not issue a `scope` claim (e.g. DID-grant tokens)
 * produce scopeless JWTs. For those requests this collector returns no rules,
 * so the scope rule group is absent from AND-evaluation and other rule groups
 * decide independently. The collector is therefore safe to include in
 * pipelines that mix OAuth and DID flows.
 *
 * For pipelines that exclusively serve scopeless flows, this collector
 * contributes nothing — prefer collectors that derive rules from identity
 * claims (e.g. DID, `sub`, role) instead.
 *
 * See https://github.com/o3co/auth.provider/issues/56 for background on why
 * the IdP asserts identity, not permissions.
 */
export class ResourceActionScopeRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		if (context.payload.scope === undefined) {
			return [];
		}
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope)];
	}
}
