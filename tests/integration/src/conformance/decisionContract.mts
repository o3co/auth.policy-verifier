// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { AuthorizationRequest } from "./types.mjs";

/** One decision as the contract reports it back. */
export interface DecisionResult {
	decision: "allow" | "deny";
	subject?: string;
	resource: string;
	action: string;
	reason: { groups: Array<{ ruleType: string; passed: boolean }> };
}

/**
 * Hooks a decision engine must provide to be checked against the verifier's
 * decision contract.
 *
 * `fixtures` let each adapter supply requests its own policy allows and denies —
 * the suite pins the shape of the contract and the relationship between its
 * parts, not any particular policy.
 */
export interface DecisionContractAdapter {
	/** Engine name, used in test titles. */
	name: string;
	/** Decide a single request. */
	decide(request: AuthorizationRequest): Promise<DecisionResult>;
	/** Decide many requests in one call, answering in request order. */
	decideBatch(requests: AuthorizationRequest[]): Promise<DecisionResult[]>;
	fixtures: {
		/** A request this engine's policy allows. */
		allowed: AuthorizationRequest;
		/** A request this engine's policy denies. */
		denied: AuthorizationRequest;
		/**
		 * Optional: one request whose outcome is decided by `context` alone, to pin
		 * that environment/relationship attributes reach the engine.
		 */
		contextDependent?: {
			request: AuthorizationRequest;
			allowingContext: Record<string, unknown>;
			denyingContext: Record<string, unknown>;
		};
	};
}

/**
 * Conformance suite pinning the decision contract
 * (o3co/auth.policy-verifier#124).
 *
 * This is the migration seam for the authorization plane: whatever engine sits
 * behind the endpoint must take `(subject, resource, action, context)`, answer
 * per request in a batch, and say *why*. An engine that cannot report a reason,
 * or that can only answer one decision per round trip, is not interchangeable
 * with this one no matter how its policy is written.
 */
export function describeDecisionContractConformance(adapter: DecisionContractAdapter): void {
	describe(`decision contract conformance — ${adapter.name}`, () => {
		const { allowed, denied, contextDependent } = adapter.fixtures;

		// The cross-check cases below make three round trips each, and an adapter
		// may be talking to a real engine over the network. vitest's 5s default is
		// tight enough that a loaded CI runner trips it, so the multi-trip cases
		// get their own budget rather than reading as a contract violation.
		const MULTI_TRIP_TIMEOUT_MS = 30_000;

		it("allows the request its policy allows", async () => {
			expect((await adapter.decide(allowed)).decision).toBe("allow");
		});

		it("denies the request its policy denies", async () => {
			expect((await adapter.decide(denied)).decision).toBe("deny");
		});

		it("names the subject, resource and action the decision was made for", async () => {
			const result = await adapter.decide(allowed);
			expect(result).toMatchObject({
				subject: allowed.subject,
				resource: allowed.resource,
				action: allowed.action,
			});
		});

		it("reports a reason on an allow", async () => {
			const result = await adapter.decide(allowed);
			expect(result.reason.groups.length).toBeGreaterThan(0);
			expect(result.reason.groups.every((group) => group.passed)).toBe(true);
		});

		it("reports which unit failed on a deny", async () => {
			const result = await adapter.decide(denied);
			expect(result.reason.groups.some((group) => !group.passed)).toBe(true);
		});

		it("answers one result per request in a batch, in request order", async () => {
			const requests = [allowed, denied, allowed];
			const results = await adapter.decideBatch(requests);

			expect(results).toHaveLength(3);
			expect(results.map((r) => [r.resource, r.action])).toEqual(
				requests.map((r) => [r.resource, r.action]),
			);
		});

		it(
			"decides a batch entry exactly as it decides that request alone",
			async () => {
				// The property that makes the batch endpoint a round-trip optimization
				// rather than a second policy surface.
				const requests = [allowed, denied];
				const batched = await adapter.decideBatch(requests);
				const singly = await Promise.all(requests.map((request) => adapter.decide(request)));

				expect(batched.map((r) => r.decision)).toEqual(singly.map((r) => r.decision));
				expect(batched.map((r) => r.reason)).toEqual(singly.map((r) => r.reason));
			},
			MULTI_TRIP_TIMEOUT_MS,
		);

		it("mixes allow and deny within one batch", async () => {
			const results = await adapter.decideBatch([allowed, denied]);
			expect(results.map((r) => r.decision)).toEqual(["allow", "deny"]);
		});

		it.runIf(contextDependent)(
			"lets request context decide the outcome",
			async () => {
				if (!contextDependent) return;
				const { request, allowingContext, denyingContext } = contextDependent;

				const allow = await adapter.decide({ ...request, context: allowingContext });
				const deny = await adapter.decide({ ...request, context: denyingContext });

				expect(allow.decision).toBe("allow");
				expect(deny.decision).toBe("deny");
			},
			MULTI_TRIP_TIMEOUT_MS,
		);
	});
}
