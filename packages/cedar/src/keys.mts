// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Attribute keys written by `RequestFactsCollector` and read (by default) by
// `CedarPolicyRuleCollector`. They exist because the rule pipeline never sees
// `CollectorContext`: a rule is a function of the merged attributes alone, so
// the request facts a Cedar policy set decides over — action, resource type,
// resource id — must be promoted into attributes by a collector first. These
// are this package's vocabulary, not core's: core's `ATTR_*` constants are
// reserved for OAuth/OIDC/RBAC concepts (AGENTS.md "Core Vocabulary Scope"),
// and "the parsed request" is not one.

import { reserveAttributeKeys } from "@o3co/auth.policy-verifier.core";

export const ATTR_REQUEST_ACTION = "requestAction" as const;
export const ATTR_REQUEST_RESOURCE_TYPE = "requestResourceType" as const;
export const ATTR_REQUEST_RESOURCE_ID = "requestResourceId" as const;
export const ATTR_REQUEST_RESOURCE_RAW = "requestResourceRaw" as const;

/** The npm package name this vocabulary is reserved under. */
export const CEDAR_ATTRIBUTE_KEY_OWNER = "@o3co/auth.policy-verifier.cedar" as const;

/** Every key above, as one list — what {@link CEDAR_ATTRIBUTE_KEY_OWNER} owns. */
export const CEDAR_ATTRIBUTE_KEYS = [
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_TYPE,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_RAW,
] as const;

/*
 * Reserved here, at module scope, beside the constants — so that adding an
 * `ATTR_*` above reserves it in the same edit, and so that the reservation is
 * in place before any collector of any package can be constructed. A
 * composition can only name `RequestFactsCollector` or
 * `CedarPolicyRuleCollector` in config by importing this package, and an import
 * runs this module body to completion first; `createApp` then initializes every
 * module before it builds a single collector from config. Reserving inside
 * `cedarPolicyModule.init` would also be early enough for that one path, and
 * too late for a library consumer that never calls `createApp`.
 *
 * What it buys: `RequestContextAttributeCollector` (builtins) refuses a mapping
 * whose `to` lands on one of these. That guard used to consult a set core
 * enumerated by hand, which could not see this package at all — and
 * `requestResourceId` is the sharp end of the gap, because
 * `RequestFactsCollector` writes it only when the parsed resource carried an
 * id. For an id-less resource such as `"document"` nothing else writes the key,
 * so a mapping `{ from = "rid", to = "requestResourceId" }` was unopposed and
 * `mapping.mts` built the Cedar resource entity out of the caller's own request
 * body: `{"resource":"document","action":"read","context":{"rid":"x"}}` decided
 * as `Document::"x"`. Where the resource *does* carry an id the two writers
 * collide and `AttributeConflictError` denies — fail-closed, but an
 * unannounced denial rather than a refusal at boot.
 */
reserveAttributeKeys({
	owner: CEDAR_ATTRIBUTE_KEY_OWNER,
	keys: CEDAR_ATTRIBUTE_KEYS,
	reason:
		"the parsed request, written by RequestFactsCollector and read by CedarPolicyRuleCollector to build the Cedar (principal, action, resource, context) request",
});
