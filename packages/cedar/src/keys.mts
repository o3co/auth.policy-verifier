// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * This package's attribute keys — the parsed request, written by
 * `RequestFactsCollector` — and their reservation in core's key registry, made
 * when this module is imported. A rule is a function of the merged attributes
 * alone, so the request facts a Cedar policy set decides over (action,
 * resource type, resource id) must be promoted into attributes by a collector
 * first; `CedarPolicyRuleCollector` reads those three by default, not the raw
 * resource. They are this package's vocabulary, not core's: core's `ATTR_*`
 * constants are reserved for OAuth/OIDC/RBAC concepts (AGENTS.md "Core
 * Vocabulary Scope").
 */

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
 * in place before any collector of any package can be constructed: naming
 * either collector in config needs this package imported, and an import runs
 * this module body first. Reserving inside `cedarPolicyModule.init` would be
 * too late for a library consumer that never calls `createApp`.
 *
 * With the keys reserved, `RequestContextAttributeCollector` (builtins)
 * refuses a mapping whose `to` lands on one of them. `requestResourceId`
 * needs it most: `RequestFactsCollector` writes it only when the parsed
 * resource carried an id, so for an id-less resource such as `"document"` a
 * mapping `{ from = "rid", to = "requestResourceId" }` would let the caller's
 * own request body name the Cedar resource entity
 * (`{"resource":"document","action":"read","context":{"rid":"x"}}` decided as
 * `document::"x"`). Where the resource does carry an id, the two writers would
 * collide and deny at request time rather than refuse at boot.
 */
reserveAttributeKeys({
	owner: CEDAR_ATTRIBUTE_KEY_OWNER,
	keys: CEDAR_ATTRIBUTE_KEYS,
	reason:
		"the parsed request, written by RequestFactsCollector and read by CedarPolicyRuleCollector to build the Cedar (principal, action, resource, context) request",
});
