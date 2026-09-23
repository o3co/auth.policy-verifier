// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that emits a configured, constant role list under
 * `ATTR_ROLES`.
 */

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Role,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_ROLES } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that returns a configured constant role list under
 * `ATTR_ROLES`, independent of the JWT payload. Each role bundles a name and
 * the permissions it implies.
 *
 * The list is copied at construction, and so is each role in it and each
 * role's `permissions` array (#255): a caller that mutates the config, its
 * array or a `Role` in it afterwards changes nothing this collector emits.
 *
 * Nothing is validated: a missing or non-iterable `roles` throws a `TypeError`
 * from the constructor, and a malformed `Role` entry is copied as it is (see
 * `copyRole`). Each collect returns a shallow copy of the list, so its `Role`
 * copies are shared between the outputs of different collects.
 *
 * Known issue (#264): a string `roles` is iterable, so
 * it is split into single characters rather than refused, as a string
 * `permissions` is in `StaticPermissionCollector`. Here the characters are
 * inert: `HasPermission` ignores those entries, since they are not objects.
 */
export class StaticRoleCollector implements AttributeCollector {
	private readonly roles: readonly Role[];

	constructor(config: { roles: Role[] }) {
		this.roles = [...config.roles].map(copyRole);
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_ROLES, [...this.roles]]]);
	}
}

/**
 * Copies one configured role: the object, and its `permissions` array.
 *
 * Nothing about the entry is validated here, and a malformed one keeps its
 * shape rather than being coerced — `HasPermission` ignores a role that is not
 * an object or whose `permissions` is not an array (#180), and spreading a bare
 * string under `permissions` would splay it into characters it then honours.
 */
function copyRole(role: Role): Role {
	if (typeof role !== "object" || role === null) return role;
	// An array is an object too: spreading it into `{ ...role }` would turn it
	// into an index-keyed object, so it is copied as an array.
	if (Array.isArray(role)) return [...role] as unknown as Role;
	return Array.isArray(role.permissions)
		? { ...role, permissions: [...role.permissions] }
		: { ...role };
}
