import { ATTR_CLIENT_ID, ATTR_USER_ID } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

export class PayloadSubjectIdCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		if (context.payload.user?.id) {
			attrs.set(ATTR_USER_ID, context.payload.user.id);
		}
		if (context.payload.client?.id) {
			attrs.set(ATTR_CLIENT_ID, context.payload.client.id);
		}
		return attrs;
	}
}
