// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { CollectorContext, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { HasPermission } from "../HasPermission.mjs";

/**
 * Rule collector that emits a single `HasPermission` rule for the
 * `{resource}.perm:{action}` permission string. Use when the effective
 * permission is encoded directly into the token's permission attribute rather
 * than derived from scopes.
 */
export class ResourceActionPermissionRuleCollector implements RuleCollector {
	async collect(context: CollectorContext): Promise<Rule[]> {
		const permission = `${context.resource.raw}.perm:${context.action}`;
		return [new HasPermission(permission)];
	}
}
