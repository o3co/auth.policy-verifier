// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Canonical attribute keys used by built-in collectors and rules. Consumers
// should reference these constants instead of raw strings so that renames stay
// centralized and TypeScript can infer literal types.

export const ATTR_SCOPES = "scopes" as const;
export const ATTR_PERMISSIONS = "permissions" as const;
export const ATTR_ROLES = "roles" as const;
export const ATTR_USER_ID = "userId" as const;
export const ATTR_CLIENT_ID = "clientId" as const;

/**
 * Every key above, as one set: the vocabulary the engine owns.
 *
 * Under the default server three of them are derived from the
 * signature-verified token — `scope` → {@link ATTR_SCOPES}, `sub` →
 * {@link ATTR_USER_ID}, `azp` → {@link ATTR_CLIENT_ID}, the mapping AGENTS.md
 * tabulates — and the other two carry the entitlements the builtin rules
 * decide from. Either way the value is the deployment's to write and never the
 * caller's, so a collector that promotes caller-supplied data refuses to write
 * here rather than joining the deployment's own contributions.
 *
 * It matters because of how the maps combine: `AttributePipeline` **unions**
 * array-valued entries across collectors, so writing to one of these keys from
 * caller-supplied data does not overwrite the deployment's value — it extends
 * it, and nothing says so. See `AttributePipeline`'s merge doc comment.
 *
 * The set lives beside the constants, not beside its caller, so that adding an
 * `ATTR_*` reserves it in the same edit. `RequestContextAttributeCollector`
 * (builtins) is the one guard that consults it today.
 */
export const RESERVED_ATTRIBUTE_KEYS: ReadonlySet<string> = new Set<string>([
	ATTR_SCOPES,
	ATTR_PERMISSIONS,
	ATTR_ROLES,
	ATTR_USER_ID,
	ATTR_CLIENT_ID,
]);
