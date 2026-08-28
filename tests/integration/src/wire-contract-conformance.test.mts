// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The reference deployment the wire contract is checked against: this
 * repository's own `createVerifyRouter`, over real HTTP.
 *
 * Everything the suite needs that is deployment-specific is here — the key
 * material, the policy that makes one request an allow and another a deny, and
 * the collector that can be made to stall. The contract itself is in
 * `conformance/fixtures/wireContract/*.json`, which is what another repository
 * implementing `VerifierEndpoint` reads.
 */

import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	RequestContextAttributeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import type {
	AttributeCollector,
	Attributes,
	CollectorContext,
	Rule,
	RuleCollector,
} from "@o3co/auth.policy-verifier.core";
import { AttributePipeline, RulePipeline } from "@o3co/auth.policy-verifier.core";
import { createVerifyRouter } from "@o3co/auth.policy-verifier.server";
import express from "express";
import { SignJWT } from "jose";
import type { Test } from "supertest";
import request from "supertest";
import {
	describeWireContractConformance,
	type WireContractAdapter,
	type WireCredential,
	type WireExchange,
	type WirePayload,
	type WireResponse,
} from "./conformance/wireContract.mjs";

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";
const SUBJECT = "user-1";
const secret = new TextEncoder().encode("wire-contract-conformance-secret");

/** The action the stalling collector below never answers for. */
const STALLING_ACTION = "stall";

/**
 * Small enough that a case can exceed them cheaply, and stated here rather than
 * defaulted so the 413 and the batch-cap cases do not depend on this package's
 * default ever staying what it is. The contract is that a limit exists and how
 * it answers, not what number a deployment chose.
 */
const MAX_BODY_BYTES = 4096;
const MAX_BATCH_SIZE = 8;

/**
 * Answers instantly for every action but one, and never for that one — so a
 * single deployment serves both the ordinary cases and the `collector_timeout`
 * deny (#115) without a second app.
 */
const stallableCollector: AttributeCollector = {
	collect: (collectorContext: CollectorContext) =>
		collectorContext.action === STALLING_ACTION
			? new Promise<Attributes>(() => {})
			: Promise.resolve(new Map<string, unknown>()),
};

/**
 * A second rule group, driven by a request-context attribute, so a deny can
 * carry a passing group beside a failing one — which is what the `satisfiedBy`
 * case (#135) needs to see in one response.
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
		attributePipeline: new AttributePipeline(
			[
				new PayloadScopeCollector(),
				new RequestContextAttributeCollector({
					attributes: [{ from: "tenant_id", to: "tenantId" }],
				}),
				stallableCollector,
			],
			// Bounds low enough that the stall is answered well inside vitest's own
			// timeout, and high enough that the in-memory collectors beside it are
			// never the thing that trips them.
			{ collectorTimeoutMs: 50, deadlineMs: 150 },
		),
		rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector(), tenantRuleCollector]),
		maxBodyBytes: MAX_BODY_BYTES,
		maxBatchSize: MAX_BATCH_SIZE,
	}),
);

/** A token this deployment verifies, with or without a `sub` claim. */
async function mintToken(subject: string | undefined): Promise<string> {
	const jwt = new SignJWT({ scope: "read:project" })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		// Required since #110; the time claims are not what this suite is about,
		// so the token simply carries valid ones.
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE);
	return (subject === undefined ? jwt : jwt.setSubject(subject)).sign(secret);
}

/** The `Authorization` header each credential kind puts on the wire. */
async function authorization(credential: WireCredential): Promise<string | undefined> {
	switch (credential) {
		case "valid":
			return `Bearer ${await mintToken(SUBJECT)}`;
		case "validWithoutSubject":
			return `Bearer ${await mintToken(undefined)}`;
		case "unverifiable":
			return "Bearer not.a.token";
		case "unsupportedScheme":
			return "Basic dXNlcjpwYXNzd29yZA==";
		case "none":
			return undefined;
	}
}

const allowed = { resource: "project:1", action: "read", context: { tenant_id: "acme" } };

/** The body text each payload kind puts on the wire, already serialized. */
function serialize(payload: WirePayload): string {
	switch (payload.kind) {
		case "json":
			return JSON.stringify(payload.value);
		case "text":
			return payload.text;
		case "overBodyLimit":
			// One character past the limit is enough, and the padding rides in
			// `context` so the body is otherwise a request this policy would decide.
			return JSON.stringify({ ...allowed, context: { blob: "x".repeat(MAX_BODY_BYTES) } });
		case "overBatchSize":
			return JSON.stringify({
				decisions: Array.from({ length: MAX_BATCH_SIZE + 1 }, () => allowed),
			});
	}
}

const adapter: WireContractAdapter = {
	name: "@o3co/auth.policy-verifier.server createVerifyRouter over HTTP",

	async send(exchange: WireExchange): Promise<WireResponse> {
		let pending: Test = request(app).post(exchange.endpoint);
		const header = await authorization(exchange.credential);
		if (header !== undefined) pending = pending.set("Authorization", header);

		// Always explicit: superagent's default for a string body is
		// form-urlencoded, and a case that means to send JSON must not depend on
		// which overload of `send` it happened to reach.
		const res = await pending
			.set("Content-Type", exchange.contentType ?? "application/json")
			.send(serialize(exchange.payload));

		return {
			status: res.status,
			contentType: res.headers["content-type"] as string | undefined,
			body: res.body,
			text: res.text,
		};
	},

	fixtures: {
		subject: SUBJECT,
		allowed,
		// `delete:project` is a scope no token here carries, so the scope group
		// fails while the tenant group passes.
		denied: { resource: "project:1", action: "delete", context: { tenant_id: "acme" } },
		// The mirror image: the scope group passes and the tenant group does not,
		// so one response carries a `satisfiedBy` and an absence of one.
		partiallySatisfied: { resource: "project:1", action: "read", context: { tenant_id: "other" } },
		stalling: { resource: "project:1", action: STALLING_ACTION, context: { tenant_id: "acme" } },
	},
};

describeWireContractConformance(adapter);
