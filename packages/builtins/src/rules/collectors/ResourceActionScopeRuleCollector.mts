// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasScope } from "../HasScope.mjs";

/** How the collector treats a token that carries no `scope` claim. */
export type ScopelessPolicy = "deny" | "skip";

const SCOPELESS_POLICIES: readonly ScopelessPolicy[] = ["deny", "skip"];

/** Config entry accepted by `ResourceActionScopeRuleCollector`. */
export interface ResourceActionScopeRuleCollectorConfig {
	/**
	 * `"deny"` (default) emits the scope rule for every request, so a scopeless
	 * token fails it. `"skip"` emits no rule for a scopeless token, leaving the
	 * scope group out of AND-evaluation.
	 */
	scopeless?: ScopelessPolicy;
}

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
 * By default the rule is emitted regardless of whether the token carries a
 * `scope` claim, so a scopeless token fails it. Dropping the rule instead would
 * remove the scope group from AND-evaluation, and in a scope-only pipeline that
 * turns "the token asserts no capability" into "every capability is allowed".
 *
 * Flows where the IdP does not issue a `scope` claim (e.g. DID-grant tokens)
 * must opt out explicitly with `{ scopeless: "skip" }`, and only in a pipeline
 * where another rule group authorizes the request — otherwise the request is
 * left with no applicable rule, which the evaluator denies.
 *
 * For pipelines that exclusively serve scopeless flows, prefer collectors that
 * derive rules from identity claims (e.g. DID, `sub`, role) instead.
 *
 * See https://github.com/o3co/auth.provider/issues/56 for background on why
 * the IdP asserts identity, not permissions.
 */
export class ResourceActionScopeRuleCollector implements RuleCollector {
	private readonly scopeless: ScopelessPolicy;

	constructor(config?: ResourceActionScopeRuleCollectorConfig) {
		const scopeless = config?.scopeless ?? "deny";
		if (!SCOPELESS_POLICIES.includes(scopeless)) {
			throw new Error(
				`ResourceActionScopeRuleCollector: scopeless must be one of ${SCOPELESS_POLICIES.join(", ")}, got "${scopeless}"`,
			);
		}
		this.scopeless = scopeless;
	}

	async collect(context: CollectorContext): Promise<Rule[]> {
		if (this.scopeless === "skip" && context.payload.scope === undefined) {
			return [];
		}
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope)];
	}
}
