// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Module } from "@o3co/auth.policy-verifier.core";
import { CedarPolicyRuleCollector } from "./CedarPolicyRuleCollector.mjs";
import { RequestFactsCollector } from "./RequestFactsCollector.mjs";

/**
 * `Module` that registers the Cedar policy rule collector and the request-facts
 * attribute collector that feeds it. Import and pass to
 * `createApp({ modules: [builtinCollectorsModule, cedarPolicyModule, ...] })`,
 * then reference both in config:
 *
 * ```hocon
 * attribute.collectors = [
 *   { collector = "RequestFactsCollector" }
 * ]
 * rule.collectors = [
 *   { collector = "CedarPolicyRuleCollector", policyDir = "config/policies" }
 * ]
 * ```
 *
 * This package holds no evaluator of its own. The policy set is evaluated by
 * whichever `CedarEngine` the deployment registered — importing
 * `@o3co/auth.policy-verifier.cedar-wasm` registers the in-process one — and
 * the collector refuses to start, naming that package, when none is. Nothing
 * of Cedar loads unless a deployment imports these packages: neither core nor
 * the server depends on them.
 */
export const cedarPolicyModule: Module = {
	name: "cedar-policy",
	async init(context) {
		context.attributeCollectorRegistry.register(
			"RequestFactsCollector",
			() => new RequestFactsCollector(),
		);
		context.ruleCollectorRegistry.register("CedarPolicyRuleCollector", (config) =>
			CedarPolicyRuleCollector.create(config),
		);
	},
};
