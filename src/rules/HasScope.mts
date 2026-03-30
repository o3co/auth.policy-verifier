import { ATTR_SCOPES } from "#/engine/keys.mjs";
import type { Attributes, Rule } from "#/engine/types.mjs";

export class HasScope implements Rule {
	readonly ruleType = "scope";
	readonly code = "invalid_scope";
	readonly message: string;

	constructor(private scope: string) {
		this.message = `Token does not have required scope: ${scope}`;
	}

	verify(attrs: Attributes): boolean {
		const scopes = (attrs.get(ATTR_SCOPES) as string[] | undefined) ?? [];
		return scopes.some((s) => this.matchScopes(s, this.scope));
	}

	private matchScopes(scope: string, required: string): boolean {
		scope = scope.toLowerCase();
		required = required.toLowerCase();

		const parts = scope.split(":");
		const [perm, resource] = parts.length === 1 ? ["read", parts[0]] : parts;

		return required === `${perm}:${resource}`;
	}
}
