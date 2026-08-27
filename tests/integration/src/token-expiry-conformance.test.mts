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
		.setIssuedAt()
		.setIssuer(ACCEPTED.issuer)
		.setAudience(ACCEPTED.audience);
	if (deviation.expOffsetSeconds !== null) {
		jwt = jwt.setExpirationTime(now + (deviation.expOffsetSeconds ?? 3600));
	}
	if (deviation.nbfOffsetSeconds !== undefined) {
		jwt = jwt.setNotBefore(now + deviation.nbfOffsetSeconds);
	}
	return jwt.sign(secret);
}

function adapterFor(name: string, jwt: VerifyRouterJwtConfig) {
	const app = createApp(jwt);
	return {
		name,
		async verify(deviation: TimeClaimDeviation) {
			const res = await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${await mint(deviation)}`)
				.send({ resource: "project:1", action: "read" });

			// 401 invalid_token means the token never reached policy evaluation. Any
			// other status means it did — the decision itself is not what this suite pins.
			return res.status === 401 ? ("rejected" as const) : ("accepted" as const);
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
// stays a working credential in every deployment that runs this mode.
describeTokenExpiryConformance(
	adapterFor("createVerifyRouter() decode-only mode (validate: false)", { validate: false }),
);
