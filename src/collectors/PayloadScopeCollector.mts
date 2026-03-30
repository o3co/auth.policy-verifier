import type { Attributes, AttributeCollector, CollectorContext } from "#/engine/types.mjs";
import { ATTR_SCOPES } from "#/engine/keys.mjs";

export class PayloadScopeCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const scopes = (context.payload as any).scopes ?? [];
		return new Map([[ATTR_SCOPES, Array.isArray(scopes) ? scopes : [scopes]]]);
	}
}
