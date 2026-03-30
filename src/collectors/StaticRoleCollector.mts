import type { Attributes, AttributeCollector, CollectorContext, Role } from "#/engine/types.mjs";
import { ATTR_ROLES } from "#/engine/keys.mjs";

export class StaticRoleCollector implements AttributeCollector {
	private roles: Role[];

	constructor(config: { roles: Role[] }) {
		this.roles = config.roles;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_ROLES, [...this.roles]]]);
	}
}
