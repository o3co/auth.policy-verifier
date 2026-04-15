import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasScope } from "./HasScope.mjs";

/**
 * Generates a HasScope rule derived from the request action and resource type.
 *
 * When the JWT payload has no `scope` claim (e.g. DID-grant tokens), no rules
 * are generated. The scope rule group is therefore absent from AND-evaluation,
 * allowing other rule groups to decide independently.
 *
 * OAuth JWTs that carry a `scope` claim are validated as before.
 */
export class ResourceActionScopeRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		if (context.payload.scope === undefined) {
			return [];
		}
		const scope = `${context.action}:${context.resource.resourceType}`;
		return [new HasScope(scope)];
	}
}
