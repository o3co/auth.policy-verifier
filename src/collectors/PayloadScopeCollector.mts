import { ATTR_SCOPES } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

export class PayloadScopeCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const scope = context.payload.scope;
		const scopes = typeof scope === "string" && scope ? scope.split(" ").filter(Boolean) : [];
		return new Map([[ATTR_SCOPES, scopes]]);
	}
}
