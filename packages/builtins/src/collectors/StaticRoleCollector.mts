// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

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
 */
export class StaticRoleCollector implements AttributeCollector {
	private roles: Role[];

	constructor(config: { roles: Role[] }) {
		this.roles = config.roles;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_ROLES, [...this.roles]]]);
	}
}
