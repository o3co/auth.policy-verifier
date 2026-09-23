// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `Module` that registers this package's two collectors,
 * `CedarPolicyRuleCollector` and `RequestFactsCollector`, with a host's
 * registries.
 */

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
 * This package holds no evaluator of its own. The policy set is evaluated by a
 * `CedarEngine`: importing `@o3co/auth.policy-verifier.cedar-wasm` registers the
 * in-process one, and this package always registers `http`, which runs against
 * a cedar-agent at `endpoint` (or `CEDAR_ENDPOINT`). With `engine` unset the
 * in-process engine wins when it is imported; otherwise `http` is chosen, and
 * with no endpoint configured it refuses to start, naming both ways out. Nothing
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
