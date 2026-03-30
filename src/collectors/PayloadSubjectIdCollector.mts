import type { Attributes, AttributeCollector, CollectorContext } from "#/engine/types.mjs";
import { ATTR_USER_ID, ATTR_CLIENT_ID } from "#/engine/keys.mjs";

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
