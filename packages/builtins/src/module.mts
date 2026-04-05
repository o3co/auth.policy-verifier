import type { Module } from "@o3co/auth.policy-verifier.core";
import { PayloadScopeCollector } from "./collectors/PayloadScopeCollector.mjs";
import { PayloadSubjectIdCollector } from "./collectors/PayloadSubjectIdCollector.mjs";
import { RequestContextCollector } from "./collectors/RequestContextCollector.mjs";
import { StaticPermissionCollector } from "./collectors/StaticPermissionCollector.mjs";
import { StaticRoleCollector } from "./collectors/StaticRoleCollector.mjs";
import { ResourceActionScopeRuleCollector } from "./rules/ResourceActionScopeRuleCollector.mjs";
import { ResourceActionPermissionRuleCollector } from "./rules/ResourceActionPermissionRuleCollector.mjs";
import { DotNotationResourceParser } from "./resource/DotNotationResourceParser.mjs";

export const builtinCollectorsModule: Module = {
	name: "builtin-collectors",
	async init(context) {
		context.attributeCollectorRegistry.register("PayloadScopeCollector", new PayloadScopeCollector());
		context.attributeCollectorRegistry.register("PayloadSubjectIdCollector", new PayloadSubjectIdCollector());
		context.attributeCollectorRegistry.register("RequestContextCollector", new RequestContextCollector());
		// TODO: These collectors require config (permissions/roles) to be useful.
		// Registered with empty defaults; config-driven instantiation is a future concern.
		context.attributeCollectorRegistry.register("StaticPermissionCollector", new StaticPermissionCollector({ permissions: [] }));
		context.attributeCollectorRegistry.register("StaticRoleCollector", new StaticRoleCollector({ roles: [] }));

		context.ruleCollectorRegistry.register("ResourceActionScopeRuleCollector", new ResourceActionScopeRuleCollector());
		context.ruleCollectorRegistry.register("ResourceActionPermissionRuleCollector", new ResourceActionPermissionRuleCollector());

		context.resourceParserRegistry.register("DotNotationResourceParser", new DotNotationResourceParser());
	},
};
