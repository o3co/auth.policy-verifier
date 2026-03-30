import { ATTR_CLIENT_ID, ATTR_USER_ID } from "#/engine/keys.mjs";
import type { AttributeCollector, Attributes, CollectorContext } from "#/engine/types.mjs";

export class PayloadSubjectIdCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attrs: Attributes = new Map();
		const payload = context.payload as any;
		if (payload.user?.id) {
			attrs.set(ATTR_USER_ID, payload.user.id);
		}
		if (payload.client?.id) {
			attrs.set(ATTR_CLIENT_ID, payload.client.id);
		}
		return attrs;
	}
}
