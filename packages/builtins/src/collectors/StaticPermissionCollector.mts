// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

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
 */
export class StaticPermissionCollector implements AttributeCollector {
	private permissions: string[];

	constructor(config: { permissions: string[] }) {
		this.permissions = config.permissions;
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_PERMISSIONS, [...this.permissions]]]);
	}
}
