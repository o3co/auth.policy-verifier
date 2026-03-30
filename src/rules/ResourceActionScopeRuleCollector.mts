import type { CollectorContext, Rule, RuleCollector } from "#/engine/types.mjs";
import { HasScope } from "./HasScope.mjs";

export class ResourceActionScopeRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope)];
	}
}
