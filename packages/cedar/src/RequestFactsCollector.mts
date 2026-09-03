// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
} from "@o3co/auth.policy-verifier.core";
import {
	ATTR_REQUEST_ACTION,
	ATTR_REQUEST_RESOURCE_ID,
	ATTR_REQUEST_RESOURCE_RAW,
	ATTR_REQUEST_RESOURCE_TYPE,
} from "./keys.mjs";

/**
 * Promotes the parsed request — `action` and the `Resource` fields — into
 * attributes, so that a rule can decide over them without touching
 * `CollectorContext`.
 *
 * `CedarPolicyRuleCollector` needs this: its rule builds the Cedar
 * `(principal, action, resource, context)` request from the merged attribute
 * map inside `verify`, and `verify` runs where the request no longer exists.
 * Only primitives are copied — string values out of the context, never a
 * reference into it — which is the legal side of the line the rule-purity
 * conformance suite draws.
 *
 * `requestResourceId` is written only when the resource parser produced one;
 * an absent id stays absent rather than becoming `""`, so downstream mapping
 * can tell "no id" from "empty id".
 */
export class RequestFactsCollector implements AttributeCollector {
	async collect(context: CollectorContext): Promise<Attributes> {
		const attributes: Attributes = new Map<string, unknown>([
			[ATTR_REQUEST_ACTION, context.action],
			[ATTR_REQUEST_RESOURCE_TYPE, context.resource.resourceType],
			[ATTR_REQUEST_RESOURCE_RAW, context.resource.raw],
		]);
		if (context.resource.resourceId !== undefined) {
			attributes.set(ATTR_REQUEST_RESOURCE_ID, context.resource.resourceId);
		}
		return attributes;
	}
}
