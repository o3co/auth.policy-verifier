// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The attribute collector that emits a configured, constant permission list
 * under `ATTR_PERMISSIONS`.
 */

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import { ATTR_PERMISSIONS } from "@o3co/auth.policy-verifier.core";

/**
 * Attribute collector that returns a configured constant permission list under
 * `ATTR_PERMISSIONS`, independent of the JWT payload. Useful for
 * environments where permissions are static per deployment.
 *
 * The list is copied at construction (#255): a caller that mutates the config
 * or its array afterwards changes nothing this collector emits.
 *
 * Only an array is accepted (#264). Anything else — a missing field, `null`, a
 * number, an object, a string — is refused with a `TypeError` naming the
 * collector and the field, so a misconfigured deployment fails at boot. A
 * string is the case that matters: it is iterable, so copying it would split
 * `"posts.*"` into single characters, and `HasPermission` honours a lone `*`
 * as grant-all.
 *
 * The entries are not checked, and a non-string one is copied as it is. It is
 * inert: `HasPermission` skips every permission that is not a string, so such
 * an entry matches no requirement and grants nothing.
 */
export class StaticPermissionCollector implements AttributeCollector {
	private readonly permissions: readonly string[];

	constructor(config: { permissions: string[] }) {
		const { permissions } = config;
		if (!Array.isArray(permissions)) {
			throw new TypeError(
				`StaticPermissionCollector: permissions must be an array (got ${permissions === null ? "null" : typeof permissions})`,
			);
		}
		this.permissions = [...permissions];
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_PERMISSIONS, [...this.permissions]]]);
	}
}
