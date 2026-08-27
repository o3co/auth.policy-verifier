// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

/** How a token deviates from the envelope the deployment under test accepts. */
export interface TokenEnvelope {
	/** `iss` claim; `null` omits it. */
	issuer?: string | null;
	/** `aud` claim; `null` omits it. */
	audience?: string | string[] | null;
	/** `typ` header; `null` omits it. */
	tokenType?: string | null;
}

/** Whether the endpoint let the token through to policy evaluation. */
export type TokenOutcome = "accepted" | "rejected";

/**
 * Hooks a decision endpoint must provide to be checked for RFC 9068 §4 token
 * validation. `accepted` declares the envelope the deployment pins; `verify`
 * mints a token deviating from it and reports whether the endpoint let it in.
 */
export interface TokenValidationAdapter {
	/** Engine name, used in test titles. */
	name: string;
	/** The envelope this deployment accepts. */
	accepted: { issuer: string; audience: string; tokenType: string };
	/**
	 * Mints a token from `accepted` with the given deviations applied, presents it
	 * to the endpoint, and reports whether it reached policy evaluation. The token
	 * is always correctly signed — this suite is about claim validation, not signatures.
	 */
	verify(envelope: TokenEnvelope): Promise<TokenOutcome>;
}

/**
 * Conformance suite pinning RFC 9068 §4 token validation
 * (o3co/auth.policy-verifier#105).
 *
 * An authorization server signs access tokens, id_tokens, refresh tokens and
 * logout tokens with the same key, and neighbouring services share issuers. A
 * decision endpoint that checks only the signature therefore accepts tokens it
 * was never the audience for. Every engine that can sit behind the verifier's
 * decision contract must reject the same set, otherwise swapping the engine
 * changes which tokens are honored.
 */
export function describeTokenValidationConformance(adapter: TokenValidationAdapter): void {
	describe(`RFC 9068 §4 token validation conformance — ${adapter.name}`, () => {
		it("accepts a token carrying the pinned issuer, audience and type", async () => {
			expect(await adapter.verify({})).toBe("accepted");
		});

		it("rejects a token minted by a foreign issuer", async () => {
			expect(await adapter.verify({ issuer: "https://foreign-issuer.test" })).toBe("rejected");
		});

		it("rejects a token minted for a foreign audience", async () => {
			expect(await adapter.verify({ audience: "https://foreign-service.test" })).toBe("rejected");
		});

		it("rejects a token with no issuer claim", async () => {
			expect(await adapter.verify({ issuer: null })).toBe("rejected");
		});

		it("rejects a token with no audience claim", async () => {
			expect(await adapter.verify({ audience: null })).toBe("rejected");
		});

		it.each(["id+jwt", "rt+jwt", "logout+jwt"])(
			"rejects a %s token signed with the same key",
			async (tokenType) => {
				expect(await adapter.verify({ tokenType })).toBe("rejected");
			},
		);

		it("rejects a token with no type header", async () => {
			expect(await adapter.verify({ tokenType: null })).toBe("rejected");
		});

		it("accepts an audience list that contains the pinned audience", async () => {
			const audience = ["https://foreign-service.test", adapter.accepted.audience];
			expect(await adapter.verify({ audience })).toBe("accepted");
		});
	});
}
