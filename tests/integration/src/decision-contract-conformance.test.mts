// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	RequestContextAttributeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import type { Attributes, Rule, RuleCollector } from "@o3co/auth.policy-verifier.core";
import { AttributePipeline, RulePipeline } from "@o3co/auth.policy-verifier.core";
import { createVerifyRouter } from "@o3co/auth.policy-verifier.server";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import {
	type DecisionContractAdapter,
	type DecisionResult,
	describeDecisionContractConformance,
} from "./conformance/decisionContract.mjs";
import type { AuthorizationRequest } from "./conformance/types.mjs";

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";
const secret = new TextEncoder().encode("decision-contract-conformance-secret");

/**
 * Rule group driven purely by a request-context attribute, so the suite's
 * context-dependent case has something to move.
 */
const tenantRuleCollector: RuleCollector = {
	async collect() {
		const rule: Rule = {
			ruleType: "tenant",
			code: "wrong_tenant",
			message: "Request is not for the acme tenant",
			verify: (attrs: Attributes) => attrs.get("tenantId") === "acme",
		};
		return [rule];
	},
};

const app = express();
app.use(
	createVerifyRouter({
		jwt: {
			validate: true,
			key: secret,
			algorithms: ["HS256"],
			issuer: ISSUER,
			audience: AUDIENCE,
			tokenType: "at+jwt",
		},
		resourceParser: new DotNotationResourceParser(),
		attributePipeline: new AttributePipeline([
			new PayloadScopeCollector(),
			new RequestContextAttributeCollector({ attributes: [{ from: "tenant_id", to: "tenantId" }] }),
		]),
		rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector(), tenantRuleCollector]),
	}),
);

/** One token carrying the subject and the scopes the fixtures rely on. */
async function mintToken(subject: string): Promise<string> {
	return new SignJWT({ scope: "read:project" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setSubject(subject)
		.sign(secret);
}

const toBody = (request: AuthorizationRequest) => ({
	resource: request.resource,
	action: request.action,
	...(request.context !== undefined ? { context: request.context } : {}),
});

const adapter: DecisionContractAdapter = {
	name: "@o3co/auth.policy-verifier.server POST /verify",

	async decide(authorizationRequest) {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${await mintToken(authorizationRequest.subject)}`)
			.send(toBody(authorizationRequest));
		return res.body as DecisionResult;
	},

	async decideBatch(authorizationRequests) {
		const subject = authorizationRequests[0].subject;
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${await mintToken(subject)}`)
			.send({ decisions: authorizationRequests.map(toBody) });
		return (res.body as { decisions: DecisionResult[] }).decisions;
	},

	fixtures: {
		allowed: {
			subject: "user-1",
			resource: "project:1",
			action: "read",
			context: { tenant_id: "acme" },
		},
		denied: {
			subject: "user-1",
			resource: "project:1",
			action: "delete",
			context: { tenant_id: "acme" },
		},
		contextDependent: {
			request: { subject: "user-1", resource: "project:1", action: "read" },
			allowingContext: { tenant_id: "acme" },
			denyingContext: { tenant_id: "other" },
		},
	},
};

describeDecisionContractConformance(adapter);
