// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The `HasPermission` rule: the subject holds a required permission, directly
 * or through one of its roles, compared exactly except where a grant carries a
 * single `*` wildcard.
 */

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
 * identifiers: compare what was written, never a normalized guess at what was
 * meant. `ResourceActionPermissionRuleCollector` builds
 * `{resource.raw}.perm:{action}` from the case-preserving parser, so
 * `Project:1` and `project:1` are two namespaces to a permission rule, as they
 * are to a scope rule.
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
 *
 * The two halves must not overlap in the required permission: a grant
 * of `"posts.*.read"` does not match `"posts.read"`, where the single `.`
 * would satisfy `startsWith` and `endsWith` at once. The wildcard may match
 * the empty string, but each character of the required permission counts
 * toward at most one half.
 */
export class HasPermission implements Rule {
	readonly ruleType = "permission";
	readonly code = "no_permission";
	readonly message: string;

	constructor(private permission: string) {
		this.message = `User does not have required permission: ${permission}`;
	}

	verify(attrs: ReadonlyAttributes): boolean {
		// Nothing about these values is taken on the cast's word: both
		// arrive from collectors, and a store-backed one can hand back anything
		// — a non-array under either key, a role whose `permissions` is missing
		// or not an array, non-string entries. Every malformed shape is ignored
		// rather than half-honoured: an entry-level guard alone still throws on
		// a non-array container, and spreading a bare string under
		// `permissions` would splay it into characters, letting a
		// one-character requirement match a value that was never a grant.
		const direct = attrs.get(ATTR_PERMISSIONS);
		const roles = attrs.get(ATTR_ROLES);
		const fromRoles = (Array.isArray(roles) ? (roles as Role[]) : []).flatMap((role) =>
			Array.isArray(role?.permissions) ? role.permissions : [],
		);
		const all = [...(Array.isArray(direct) ? direct : []), ...fromRoles];

		// Non-string entries never match and never throw, as in HasScope.
		return all.some((p) => typeof p === "string" && this.match(p, this.permission));
	}

	private match(permission: string, required: string): boolean {
		if (permission === "*") return true;
		if (permission === required) return true;

		if (permission.includes("*")) {
			// A grant with more than one wildcard never matches: the two-part
			// split below would drop everything after the second segment ("a*c*b"
			// read as "a*c") and over-grant.
			if ((permission.match(/\*/g) ?? []).length > 1) return false;

			const [prefix, suffix] = permission.split("*");
			// The halves must not overlap in `required`: "posts.*.read"
			// must not match "posts.read", where the single "." satisfies both
			// startsWith and endsWith. Length is the whole check — the wildcard
			// may match the empty string, but a character may only count toward
			// one half.
			if (required.length < prefix.length + suffix.length) return false;
			return (!prefix || required.startsWith(prefix)) && (!suffix || required.endsWith(suffix));
		}

		return false;
	}
}
