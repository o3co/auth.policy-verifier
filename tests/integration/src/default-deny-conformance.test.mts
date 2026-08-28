// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { ResourceActionScopeRuleCollector } from "@o3co/auth.policy-verifier.builtins";
import type { Attributes, CollectorContext } from "@o3co/auth.policy-verifier.core";
import { evaluate, markUntrustedRequestContext } from "@o3co/auth.policy-verifier.core";
import {
	type AuthorizationRequest,
	describeDefaultDenyConformance,
} from "./conformance/defaultDeny.mjs";

/** Maps an engine-neutral request onto this repo's `CollectorContext`. */
function toCollectorContext(request: AuthorizationRequest): CollectorContext {
	const [resourceType, resourceId] = request.resource.split(":");
	return {
		payload: { sub: request.subject },
		resource: { raw: request.resource, resourceType, resourceId },
		action: request.action,
		// The engine-neutral request's `context` is the caller's own, the same as
		// an HTTP body's — an adapter marks it on the way in, exactly as the verify
		// route does.
		requestContext: request.context ? markUntrustedRequestContext(request.context) : undefined,
	};
}

describeDefaultDenyConformance({
	name: "@o3co/auth.policy-verifier.core evaluate()",

	async decideWithNoPolicy(_request) {
		// No rule collector configured at all → nothing is collected.
		const attrs: Attributes = new Map();
		return evaluate(attrs, []);
	},

	async decideWithNonApplicablePolicy(request) {
		// A rule collector is configured, but it produces nothing for this request:
		// the scope collector opted into `scopeless: "skip"` facing a scopeless token.
		const collector = new ResourceActionScopeRuleCollector({ scopeless: "skip" });
		const rules = await collector.collect(toCollectorContext(request));
		return evaluate(new Map(), rules);
	},
});
