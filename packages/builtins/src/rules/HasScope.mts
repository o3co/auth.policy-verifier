// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Attributes, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_SCOPES } from "@o3co/auth.policy-verifier.core";

/**
 * Rule that passes when the token carries a scope matching the required
 * `perm:resource` form (case-insensitive). A granted scope written as a single
 * token (no `:`) is treated as `read:<token>`, matching OAuth2 conventions
 * where bare resource names imply read access.
 */
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
