import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Role,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_ROLES } from "@o3co/auth.policy-verifier.core";

export class StaticRoleCollector implements AttributeCollector {
	private roles: Role[];

	constructor(config: { roles: Role[] }) {
		this.roles = config.roles;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_ROLES, [...this.roles]]]);
	}
}
