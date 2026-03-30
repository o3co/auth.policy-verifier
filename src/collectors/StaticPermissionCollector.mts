import type { Attributes, AttributeCollector, CollectorContext } from "#/engine/types.mjs";
import { ATTR_PERMISSIONS } from "#/engine/keys.mjs";

export class StaticPermissionCollector implements AttributeCollector {
	private permissions: string[];

	constructor(config: { permissions: string[] }) {
		this.permissions = config.permissions;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_PERMISSIONS, [...this.permissions]]]);
	}
}
