import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";

export class PayloadScopeCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const scope = context.payload.scope;
		const scopes = typeof scope === "string" && scope ? scope.split(" ").filter(Boolean) : [];
		return new Map([[ATTR_SCOPES, scopes]]);
	}
}
