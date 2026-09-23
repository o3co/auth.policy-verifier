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
 * or its array afterwards changes nothing this collector emits. Nothing is
 * validated: a missing or non-iterable `permissions` throws a `TypeError` from
 * the constructor.
 *
 * Known issue (#264): a string `permissions` is
 * iterable, so it is split into single characters rather than refused — and a
 * lone `*` among them is treated by `HasPermission` as grant-all.
 */
export class StaticPermissionCollector implements AttributeCollector {
	private readonly permissions: readonly string[];

	constructor(config: { permissions: string[] }) {
		this.permissions = [...config.permissions];
	}

	async collect(_context: CollectorContext): Promise<Attributes> {
		return new Map([[ATTR_PERMISSIONS, [...this.permissions]]]);
	}
}
