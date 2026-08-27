// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

/**
 * How a token's time claims deviate from a fresh, currently-valid token.
 * `undefined` leaves the suite's default (a valid value); `null` omits the
 * claim entirely.
 */
export interface TimeClaimDeviation {
	/** `exp` claim as a unix-seconds offset from now; `null` omits it. */
	expOffsetSeconds?: number | null;
	/** `nbf` claim as a unix-seconds offset from now; omitted by default. */
	nbfOffsetSeconds?: number;
}

/** Whether the endpoint let the token through to policy evaluation. */
export type TimeClaimOutcome = "accepted" | "rejected";

/**
 * Hooks a decision endpoint must provide to be checked for time-claim
 * enforcement. `verify` mints an otherwise-acceptable token with the given
 * deviations applied, presents it, and reports whether it reached policy
 * evaluation.
 */
export interface TokenExpiryAdapter {
	/** Deployment mode name, used in test titles. */
	name: string;
	verify(deviation: TimeClaimDeviation): Promise<TimeClaimOutcome>;
}

/**
 * Conformance suite pinning `exp` / `nbf` enforcement
 * (o3co/auth.policy-verifier#106).
 *
 * Every deployment mode of the verifier must honour a token's own lifetime —
 * including the decode-only mode that skips signature verification: skipping
 * the signature is an (acknowledged, test-only) trust decision about the
 * issuer, but honouring an expired token is simply wrong in every mode, and is
 * what turns a leaked old token into a permanent credential.
 *
 * Absence of `exp` is deliberately accepted: `jwtVerify` validates time claims
 * only when present, and the decode path mirrors those semantics exactly so
 * the two modes never disagree about the same token.
 */
export function describeTokenExpiryConformance(adapter: TokenExpiryAdapter): void {
	describe(`token time-claim conformance — ${adapter.name}`, () => {
		it("accepts a fresh token", async () => {
			expect(await adapter.verify({})).toBe("accepted");
		});

		it("rejects an expired token", async () => {
			expect(await adapter.verify({ expOffsetSeconds: -3600 })).toBe("rejected");
		});

		it("rejects a token that is not yet valid", async () => {
			expect(await adapter.verify({ nbfOffsetSeconds: 3600 })).toBe("rejected");
		});

		it("accepts a token carrying no exp claim (jwtVerify parity)", async () => {
			expect(await adapter.verify({ expOffsetSeconds: null })).toBe("accepted");
		});
	});
}
