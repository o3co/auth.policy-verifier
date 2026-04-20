// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Module } from "@o3co/auth.policy-verifier.core";
import { PayloadScopeCollector } from "./collectors/PayloadScopeCollector.mjs";
import { PayloadSubjectIdCollector } from "./collectors/PayloadSubjectIdCollector.mjs";
import { StaticPermissionCollector } from "./collectors/StaticPermissionCollector.mjs";
import { StaticRoleCollector } from "./collectors/StaticRoleCollector.mjs";
import { DotNotationResourceParser } from "./resource/DotNotationResourceParser.mjs";
import { ResourceActionPermissionRuleCollector } from "./rules/collectors/ResourceActionPermissionRuleCollector.mjs";
import { ResourceActionScopeRuleCollector } from "./rules/collectors/ResourceActionScopeRuleCollector.mjs";

/**
 * `Module` that registers the built-in attribute collectors, rule collectors,
 * and resource parser with a policy-verifier server. Import and pass to
 * `createApp({ modules: [builtinCollectorsModule, ...] })`.
 */
export const builtinCollectorsModule: Module = {
	name: "builtin-collectors",
	async init(context) {
		// Attribute collector factories
		context.attributeCollectorRegistry.register(
			"PayloadScopeCollector",
			() => new PayloadScopeCollector(),
		);
		context.attributeCollectorRegistry.register(
			"PayloadSubjectIdCollector",
			() => new PayloadSubjectIdCollector(),
		);
		context.attributeCollectorRegistry.register(
			"StaticPermissionCollector",
			(config) => new StaticPermissionCollector(config),
		);
		context.attributeCollectorRegistry.register(
			"StaticRoleCollector",
			(config) => new StaticRoleCollector(config),
		);

		// Rule collector factories
		context.ruleCollectorRegistry.register(
			"ResourceActionScopeRuleCollector",
			() => new ResourceActionScopeRuleCollector(),
		);
		context.ruleCollectorRegistry.register(
			"ResourceActionPermissionRuleCollector",
			() => new ResourceActionPermissionRuleCollector(),
		);

		// Resource parser factories
		context.resourceParserRegistry.register(
			"DotNotationResourceParser",
			() => new DotNotationResourceParser(),
		);
	},
};
