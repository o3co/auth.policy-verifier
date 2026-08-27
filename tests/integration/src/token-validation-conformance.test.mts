// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import { AttributePipeline, RulePipeline } from "@o3co/auth.policy-verifier.core";
import { createVerifyRouter } from "@o3co/auth.policy-verifier.server";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import {
	describeTokenValidationConformance,
	type TokenEnvelope,
} from "./conformance/tokenValidation.mjs";

const ACCEPTED = {
	issuer: "https://issuer.test",
	audience: "https://api.test",
	tokenType: "at+jwt",
};

const secret = new TextEncoder().encode("token-validation-conformance-secret");

const app = express();
app.use(
	createVerifyRouter({
		jwt: { validate: true, key: secret, algorithms: ["HS256"], ...ACCEPTED },
		resourceParser: new DotNotationResourceParser(),
		attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
		rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
	}),
);

/** Mints a correctly-signed token from ACCEPTED with the envelope's deviations applied. */
async function mint(envelope: TokenEnvelope): Promise<string> {
	const tokenType = envelope.tokenType === undefined ? ACCEPTED.tokenType : envelope.tokenType;
	const issuer = envelope.issuer === undefined ? ACCEPTED.issuer : envelope.issuer;
	const audience = envelope.audience === undefined ? ACCEPTED.audience : envelope.audience;

	let jwt = new SignJWT({ scope: "read:project" })
		.setProtectedHeader(tokenType === null ? { alg: "HS256" } : { alg: "HS256", typ: tokenType })
		.setIssuedAt()
		// iat and exp are both mandatory now (#110). This suite is about the RFC
		// 9068 §4 envelope, so its tokens carry valid time claims and deviate only
		// in iss / aud / typ; token lifetime is pinned by the sibling expiry suite.
		.setExpirationTime("1h");
	if (issuer !== null) jwt = jwt.setIssuer(issuer);
	if (audience !== null) jwt = jwt.setAudience(audience);
	return jwt.sign(secret);
}

describeTokenValidationConformance({
	name: "@o3co/auth.policy-verifier.server createVerifyRouter()",
	accepted: ACCEPTED,

	async verify(envelope) {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await mint(envelope)}`)
			.send({ resource: "project:1", action: "read" });

		// 401 invalid_token means the token never reached policy evaluation. Any other
		// status means it did — the decision itself is not what this suite pins.
		return res.status === 401 ? "rejected" : "accepted";
	},
});
