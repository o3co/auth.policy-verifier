import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasPermission } from "./HasPermission.mjs";

export class ResourceActionPermissionRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		const permission = `${context.resource.raw}.perm:${context.action}`;
		return [new HasPermission(permission)];
	}
}
