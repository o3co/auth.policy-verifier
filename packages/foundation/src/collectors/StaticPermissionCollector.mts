import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS } from "@o3co/auth.policy-verifier.core";

export class StaticPermissionCollector implements AttributeCollector {
	private permissions: string[];

	constructor(config: { permissions: string[] }) {
		this.permissions = config.permissions;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_PERMISSIONS, [...this.permissions]]]);
	}
}
