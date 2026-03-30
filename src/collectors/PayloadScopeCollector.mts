import { ATTR_SCOPES } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

export class PayloadScopeCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const scopes = context.payload.scopes ?? [];
		return new Map([[ATTR_SCOPES, Array.isArray(scopes) ? scopes : [scopes]]]);
	}
}
