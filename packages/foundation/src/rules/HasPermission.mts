import type { Attributes, Role, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS, ATTR_ROLES } from "@o3co/auth.policy-verifier.core";

export class HasPermission implements Rule {
	readonly ruleType = "permission";
	readonly code = "no_permission";
	readonly message: string;

	constructor(private permission: string) {
		this.message = `User does not have required permission: ${permission}`;
	}

	verify(attrs: Attributes): boolean {
		const direct = (attrs.get(ATTR_PERMISSIONS) as string[] | undefined) ?? [];
		const fromRoles = ((attrs.get(ATTR_ROLES) as Role[] | undefined) ?? []).flatMap(
			(role) => role.permissions,
		);
		const all = [...direct, ...fromRoles];

		return all.some((p) => this.match(p, this.permission));
	}

	private match(permission: string, required: string): boolean {
		permission = permission.toLowerCase();
		required = required.toLowerCase();

		if (permission === "*") return true;
		if (permission === required) return true;

		if (permission.includes("*")) {
			const [prefix, suffix] = permission.split("*");
			return (!prefix || required.startsWith(prefix)) && (!suffix || required.endsWith(suffix));
		}

		return false;
	}
}
