import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasScope } from "./HasScope.mjs";

export class ResourceActionScopeRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope)];
	}
}
