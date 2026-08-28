// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { ReadonlyAttributes, Role, Rule } from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS, ATTR_ROLES } from "@o3co/auth.policy-verifier.core";

/**
 * Rule that passes when the subject holds the required permission, either
 * directly via `ATTR_PERMISSIONS` or transitively through a role in
 * `ATTR_ROLES`.
 *
 * ## Matching
 *
 * Comparison is **exact and case-sensitive**, the same philosophy `HasScope`
 * applies to scope values and `DotNotationResourceParser` applies to resource
 * identifiers (#116, #117): compare what was written, never a normalized guess
 * at what was meant. This rule matched case-insensitively until #155, which
 * put permissions on the wrong side of the line those two argued —
 * `ResourceActionPermissionRuleCollector` builds `{resource.raw}.perm:{action}`
 * from the case-preserving parser, so `Project:1` and `project:1` were two
 * namespaces to a scope rule and one to a permission rule. One vocabulary, one
 * matching discipline.
 *
 * ## Wildcards
 *
 * A granted permission of `"*"` matches everything, and a granted permission
 * may contain a single `*` as prefix, suffix, or middle separator (e.g.
 * `"posts.*"`, `"*.read"`, `"posts.*.read"`). This is not an exception to the
 * no-normalization rule: a wildcard is match structure the policy author
 * **wrote into the grant**, not a rewrite of both sides behind their back. The
 * literal halves around the `*` still compare exactly and case-sensitively.
 * Multiple wildcards are rejected outright because the two-part split would
 * silently drop segments and over-grant.
 */
export class HasPermission implements Rule {
	readonly ruleType = "permission";
	readonly code = "no_permission";
	readonly message: string;

	constructor(private permission: string) {
		this.message = `User does not have required permission: ${permission}`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		const direct = (attrs.get(ATTR_PERMISSIONS) as string[] | undefined) ?? [];
		const fromRoles = ((attrs.get(ATTR_ROLES) as Role[] | undefined) ?? []).flatMap(
			(role) => role.permissions,
		);
		const all = [...direct, ...fromRoles];

		return all.some((p) => this.match(p, this.permission));
	}

	private match(permission: string, required: string): boolean {
		if (permission === "*") return true;
		if (permission === required) return true;

		if (permission.includes("*")) {
			// Reject any granted permission that contains more than one wildcard.
			// With 2+ wildcards, split("*") produces 3+ parts, but the destructuring
			// `const [prefix, suffix] = ...` silently drops everything after the second
			// segment. For example, "a*c*b" is treated as "a*c" (endsWith "c" instead of
			// "b"), which can grant broader access than intended. Returning false is the
			// safe default: deny rather than over-grant. Single-wildcard permissions
			// (e.g. "posts.*" or "*.read") continue to work as before.
			if ((permission.match(/\*/g) ?? []).length > 1) return false;

			const [prefix, suffix] = permission.split("*");
			return (!prefix || required.startsWith(prefix)) && (!suffix || required.endsWith(suffix));
		}

		return false;
	}
}
