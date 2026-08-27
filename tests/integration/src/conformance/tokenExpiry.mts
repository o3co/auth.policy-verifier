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
	/** `iat` claim as a unix-seconds offset from now; `null` omits it. Defaults to now. */
	iatOffsetSeconds?: number | null;
}

/**
 * Time-claim knobs the deployment under test is configured with. Omitted means
 * the deployment's own defaults, which is what most cases pin.
 */
export interface TimeClaimOptions {
	/** Ceiling on `now - iat`, in seconds. */
	maxTokenAgeSeconds?: number;
	/** Skew allowance applied to every time-claim comparison, in seconds. */
	clockToleranceSeconds?: number;
}

/** Whether the endpoint let the token through to policy evaluation. */
export type TimeClaimOutcome = "accepted" | "rejected";

/**
 * Hooks a decision endpoint must provide to be checked for time-claim
 * enforcement. `verify` mints an otherwise-acceptable token with the given
 * deviations applied, presents it to an endpoint configured with `options`,
 * and reports whether it reached policy evaluation.
 */
export interface TokenExpiryAdapter {
	/** Deployment mode name, used in test titles. */
	name: string;
	verify(deviation: TimeClaimDeviation, options?: TimeClaimOptions): Promise<TimeClaimOutcome>;
}

/**
 * Conformance suite pinning `exp` / `nbf` / `iat` enforcement
 * (o3co/auth.policy-verifier#106, #110).
 *
 * Every deployment mode of the verifier must honour a token's own lifetime —
 * including the decode-only mode that skips signature verification: skipping
 * the signature is an (acknowledged, test-only) trust decision about the
 * issuer, but honouring an expired token is simply wrong in every mode, and is
 * what turns a leaked old token into a permanent credential.
 *
 * `exp` is **required**, not merely honoured when present (#110). jose's
 * `jwtVerify` checks time claims only when they appear, which left a token
 * minted (or forged) without `exp` valid forever — a fail-closed authorization
 * service must not depend on the issuer's discipline for expiry. `maxTokenAge`
 * closes the same hole from the other side: an `exp` the issuer set years out
 * is still bounded by how long ago the token was issued, which is why `iat` is
 * required too (RFC 9068 §2.2 requires both claims of an access token).
 *
 * Both deployment modes are held to the identical outcome for the identical
 * token: the decode path restates these checks by hand, so this suite is what
 * keeps the two from disagreeing.
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

		// #110: the eternal token. Nothing about a token without `exp` says when
		// it stops being a credential, so it never does.
		it("rejects a token carrying no exp claim", async () => {
			expect(await adapter.verify({ expOffsetSeconds: null })).toBe("rejected");
		});

		// `maxTokenAge` is measured from `iat`, so a token without one cannot be
		// bounded at all — refuse it rather than fall back to trusting `exp`.
		it("rejects a token carrying no iat claim", async () => {
			expect(await adapter.verify({ iatOffsetSeconds: null })).toBe("rejected");
		});

		it("rejects an ancient token whose exp is still in the future", async () => {
			expect(
				await adapter.verify(
					{ iatOffsetSeconds: -3600, expOffsetSeconds: 86_400 },
					{ maxTokenAgeSeconds: 60 },
				),
			).toBe("rejected");
		});

		it("accepts that same token where the configured maxTokenAge covers its age", async () => {
			expect(
				await adapter.verify(
					{ iatOffsetSeconds: -3600, expOffsetSeconds: 86_400 },
					{ maxTokenAgeSeconds: 7200 },
				),
			).toBe("accepted");
		});

		it("rejects a token issued in the future", async () => {
			expect(await adapter.verify({ iatOffsetSeconds: 3600, expOffsetSeconds: 7200 })).toBe(
				"rejected",
			);
		});

		it("rejects a just-expired token when no clock tolerance is configured", async () => {
			expect(await adapter.verify({ expOffsetSeconds: -30 })).toBe("rejected");
		});

		it("accepts that same token within a configured clock tolerance", async () => {
			expect(await adapter.verify({ expOffsetSeconds: -30 }, { clockToleranceSeconds: 60 })).toBe(
				"accepted",
			);
		});

		it("applies the clock tolerance to nbf as well", async () => {
			expect(await adapter.verify({ nbfOffsetSeconds: 30 })).toBe("rejected");
			expect(await adapter.verify({ nbfOffsetSeconds: 30 }, { clockToleranceSeconds: 60 })).toBe(
				"accepted",
			);
		});

		it("applies the clock tolerance to maxTokenAge as well", async () => {
			const ancient = { iatOffsetSeconds: -90, expOffsetSeconds: 86_400 };
			expect(await adapter.verify(ancient, { maxTokenAgeSeconds: 60 })).toBe("rejected");
			expect(
				await adapter.verify(ancient, { maxTokenAgeSeconds: 60, clockToleranceSeconds: 60 }),
			).toBe("accepted");
		});
	});
}
