// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import { AttributePipeline, RulePipeline } from "@o3co/auth.policy-verifier.core";
import { createVerifyRouter, type VerifyRouterJwtConfig } from "@o3co/auth.policy-verifier.server";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import {
	describeTokenExpiryConformance,
	type TimeClaimDeviation,
	type TimeClaimOptions,
} from "./conformance/tokenExpiry.mjs";

const ACCEPTED = {
	issuer: "https://issuer.test",
	audience: "https://api.test",
	tokenType: "at+jwt",
};

const secret = new TextEncoder().encode("token-expiry-conformance-secret");

function createApp(jwt: VerifyRouterJwtConfig) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
		}),
	);
	return app;
}

/** Mints a correctly-signed, otherwise-acceptable token with the deviations applied. */
async function mint(deviation: TimeClaimDeviation): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	let jwt = new SignJWT({ scope: "read:project" })
		.setProtectedHeader({ alg: "HS256", typ: ACCEPTED.tokenType })
		.setIssuer(ACCEPTED.issuer)
		.setAudience(ACCEPTED.audience);
	if (deviation.iatOffsetSeconds !== null) {
		jwt = jwt.setIssuedAt(now + (deviation.iatOffsetSeconds ?? 0));
	}
	if (deviation.expOffsetSeconds !== null) {
		jwt = jwt.setExpirationTime(now + (deviation.expOffsetSeconds ?? 3600));
	}
	if (deviation.nbfOffsetSeconds !== undefined) {
		jwt = jwt.setNotBefore(now + deviation.nbfOffsetSeconds);
	}
	return jwt.sign(secret);
}

function adapterFor(name: string, jwt: VerifyRouterJwtConfig) {
	return {
		name,
		async verify(deviation: TimeClaimDeviation, options: TimeClaimOptions = {}) {
			// Built per call: the time-claim knobs under test are router config, so
			// a case that pins one has to stand up the router configured with it.
			const app = createApp({ ...jwt, ...options });
			const res = await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${await mint(deviation)}`)
				.send({ resource: "project:1", action: "read" });

			// 401 invalid_token means the token never reached policy evaluation;
			// 200/403 means it did — the decision itself is not what this suite
			// pins. Anything else (400/500) is a broken harness, not an answer,
			// and must fail the test rather than masquerade as either outcome.
			if (res.status === 401) return "rejected" as const;
			if (res.status === 200 || res.status === 403) return "accepted" as const;
			throw new Error(`unexpected status ${res.status}: ${JSON.stringify(res.body)}`);
		},
	};
}

describeTokenExpiryConformance(
	adapterFor("createVerifyRouter() verifying mode (validate: true)", {
		validate: true,
		key: secret,
		algorithms: ["HS256"],
		...ACCEPTED,
	}),
);

// The decode-only mode skips signature verification, but a token's own
// lifetime must still be honoured (#106) — otherwise a leaked expired token
// stays a working credential in every deployment that runs this mode. The
// same holds for the claims #110 made mandatory: a decode-only deployment
// that accepted an eternal token would disagree with the verifying one about
// the very token this suite mints.
describeTokenExpiryConformance(
	adapterFor("createVerifyRouter() decode-only mode (validate: false)", {
		validate: false,
		allowInsecureDecode: true,
	}),
);
