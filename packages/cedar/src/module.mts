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
 * Nothing loads unless this module is imported: the WASM evaluator is a
 * dependency of this package, not of core or the server.
 */
export const cedarPolicyModule: Module = {
	name: "cedar-policy",
	async init(context) {
		context.attributeCollectorRegistry.register(
			"RequestFactsCollector",
			() => new RequestFactsCollector(),
		);
		context.ruleCollectorRegistry.register(
			"CedarPolicyRuleCollector",
			(config) => new CedarPolicyRuleCollector(config),
		);
	},
};
