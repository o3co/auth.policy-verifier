// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The rule collector that emits one `HasScope` rule for the request's
 * `{action}:{resourceType}` scope, with a configurable treatment of tokens that
 * carry no scope claim.
 */

import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { DEFAULT_SCOPE_CLAIM, resolveClaimName } from "../../collectors/_claims.mjs";
import { HasScope } from "../HasScope.mjs";

/** How the collector treats a token that carries no scope claim (`scope`, or the configured `claim`). */
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
	/**
	 * Forwarded to `HasScope`. `false` (default) compares granted scopes
	 * literally; `true` additionally treats a bare granted scope `x` as
	 * `read:x`. See `HasScopeOptions.allowBareScopeRewrite`.
	 */
	allowBareScopeRewrite?: boolean;
	/**
	 * The claim whose presence says the token asserted scopes. Defaults
	 * to `scope`; set it to what `PayloadScopeCollector` reads (`scp` for Okta)
	 * so the two look at the same claim — each keeps its own option, and
	 * nothing checks that both were given the same name. Only presence is
	 * checked here: a claim holding no usable scope list (`""`, a number)
	 * yields no scopes from `PayloadScopeCollector` but still counts as scoped
	 * under `scopeless: "skip"`.
	 */
	claim?: string;
}

/**
 * Generates a HasScope rule derived from the request action and resource type.
 *
 * ## Scope as capability ceiling
 *
 * The JWT `scope` claim represents what the session **can request** — a
 * capability ceiling — not what the session **has been granted**; the full
 * rule pipeline decides the latter. This collector enforces the ceiling only:
 * it produces a `HasScope` rule for the requested `{action}:{resourceType}`,
 * which the token's scopes must satisfy, compared exactly and case-sensitively.
 * An issuer that emits bare resource names (`project` rather than
 * `read:project`) must opt in with `{ allowBareScopeRewrite: true }`.
 *
 * ## Scopeless tokens
 *
 * By default the rule is emitted whether or not the token carries the scope
 * claim, so a scopeless token fails it. Dropping the rule instead would remove
 * the scope group from AND-evaluation, and in a scope-only pipeline that turns
 * "the token asserts no capability" into "every capability is allowed".
 *
 * Flows where the IdP issues no scope claim (e.g. DID-grant tokens) must opt
 * out explicitly with `{ scopeless: "skip" }`, and only in a pipeline where
 * another rule group authorizes the request — otherwise the request is left
 * with no applicable rule, which the evaluator denies by default and allows
 * under `onEmptyRuleSet: "allow"`. A pipeline that serves only scopeless
 * flows should derive rules from identity claims (DID, `sub`, role) instead.
 */
export class ResourceActionScopeRuleCollector implements RuleCollector {
	private readonly scopeless: ScopelessPolicy;
	private readonly allowBareScopeRewrite: boolean;
	private readonly claim: string;

	constructor(config?: ResourceActionScopeRuleCollectorConfig) {
		this.claim = resolveClaimName(
			"ResourceActionScopeRuleCollector",
			config?.claim,
			DEFAULT_SCOPE_CLAIM,
		);
		const scopeless = config?.scopeless ?? "deny";
		if (!SCOPELESS_POLICIES.includes(scopeless)) {
			throw new Error(
				`ResourceActionScopeRuleCollector: scopeless must be one of ${SCOPELESS_POLICIES.join(", ")}, got "${scopeless}"`,
			);
		}
		this.scopeless = scopeless;

		// Validate the raw value before defaulting: `?? false` alone would treat an
		// explicit `null` as "unset" and silently accept a misconfiguration. Only
		// an absent key may fall back to the default.
		const rawRewrite: unknown = config?.allowBareScopeRewrite;
		if (rawRewrite !== undefined && typeof rawRewrite !== "boolean") {
			throw new Error(
				`ResourceActionScopeRuleCollector: allowBareScopeRewrite must be a boolean, got "${rawRewrite}"`,
			);
		}
		this.allowBareScopeRewrite = rawRewrite ?? false;
	}

	async collect(context: CollectorContext): Promise<Rule[]> {
		if (this.scopeless === "skip" && context.subject[this.claim] === undefined) {
			return [];
		}
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope, { allowBareScopeRewrite: this.allowBareScopeRewrite })];
	}
}
