// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Decision } from "@o3co/auth.policy-verifier.core";
import { describe, expect, it } from "vitest";

/**
 * Engine-neutral authorization request. Deliberately shaped as
 * `(subject, resource, action, context)` so an adapter for a heavy-class engine
 * (OPA, OpenFGA, Cedar) can satisfy the same suite.
 */
export interface AuthorizationRequest {
	subject: string;
	resource: string;
	action: string;
	context?: Record<string, unknown>;
}

/**
 * Hooks a decision engine must provide to be checked for default-deny.
 *
 * The suite never constructs an engine's policy itself — each adapter knows how
 * to put its own engine into the two states under test, which is what lets the
 * same assertions run against this repo's evaluator and against a heavy-class
 * engine placed behind the same decision contract.
 */
export interface DefaultDenyAdapter {
	/** Engine name, used in test titles. */
	name: string;
	/** Decide with no policy loaded at all. */
	decideWithNoPolicy(request: AuthorizationRequest): Promise<Decision>;
	/** Decide with a policy loaded that produces no applicable rule for this request. */
	decideWithNonApplicablePolicy(request: AuthorizationRequest): Promise<Decision>;
}

const REQUEST: AuthorizationRequest = {
	subject: "user:1",
	resource: "document:1",
	action: "read",
	context: {},
};

/**
 * Conformance suite pinning the default-deny guarantee (o3co/auth.policy-verifier#104).
 *
 * A request that no policy speaks to is unauthorized, not unrestricted. Every
 * engine that can sit behind the verifier's decision contract must agree on
 * this, otherwise swapping the engine silently changes who is allowed in.
 */
export function describeDefaultDenyConformance(adapter: DefaultDenyAdapter): void {
	describe(`default-deny conformance — ${adapter.name}`, () => {
		it("denies when no policy is loaded", async () => {
			const decision = await adapter.decideWithNoPolicy(REQUEST);
			expect(decision.decision).toBe("deny");
		});

		it("denies when the loaded policy has no applicable rule for the request", async () => {
			const decision = await adapter.decideWithNonApplicablePolicy(REQUEST);
			expect(decision.decision).toBe("deny");
		});

		it("reports a reason on the default deny", async () => {
			const decision = await adapter.decideWithNoPolicy(REQUEST);
			expect(decision).toMatchObject({
				decision: "deny",
				code: expect.any(String),
				message: expect.any(String),
			});
		});
	});
}
