// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/**
 * A delegated token's range, decided at `/verify` together with the policies
 * (the builtins `DelegationRangeCollector` and `DelegationRangeRuleCollector`
 * beside the scope rule): a token that carries a range is allowed only a
 * request whose path — the resource, then the action — lies within one of its
 * entries, and a token without a range is decided as it would be without
 * them.
 */
import {
	DelegationRangeCollector,
	DelegationRangeRuleCollector,
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import { AttributePipeline, consoleLogger, RulePipeline } from "@o3co/auth.policy-verifier.core";
import express from "express";
import { type KeyObject, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createTokenAuthenticator, HS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";
const TYPE = "delegation";
const key = await HS256KeyResolverFactory({ secret: "11".repeat(32) });
const quiet = { ...consoleLogger, info: () => {}, warn: () => {}, error: () => {} };

const app = express().use(
	createVerifyRouter({
		authenticator: createTokenAuthenticator(
			{
				validate: true,
				key: key.key,
				algorithms: key.algorithms,
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			quiet,
		),
		logger: quiet,
		resourceParser: new DotNotationResourceParser(),
		attributePipeline: new AttributePipeline([
			new PayloadScopeCollector(),
			new DelegationRangeCollector({ type: TYPE }),
		]),
		rulePipeline: new RulePipeline([
			new ResourceActionScopeRuleCollector(),
			new DelegationRangeRuleCollector({ type: TYPE }),
		]),
	}),
);

const tokenWith = (claims: Record<string, unknown>) =>
	new SignJWT({ sub: "user-1", scope: "run:project.report", ...claims })
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(key.key as KeyObject);

const verify = async (token: string, resource: string) =>
	request(app)
		.post("/verify")
		.set("Authorization", `Bearer ${token}`)
		.send({ resource, action: "run" });

const delegated = () =>
	tokenWith({
		act: { sub: "batch-client" },
		authorization_details: [{ type: TYPE, path: "project:p1.report" }],
	});

describe("/verify with a delegated token's range", () => {
	it("allows a request within the range", async () => {
		const res = await verify(await delegated(), "project:p1.report:r7");

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("denies a request the policies allow but the range does not contain", async () => {
		const res = await verify(await delegated(), "project:p2.report:r7");

		expect(res.status).toBe(403);
		expect(res.body.code).toBe("outside_delegation_range");
	});

	// A dotted action would re-split the joined path: `project:p1` with
	// `report.delete` would read as `project:p1.report.delete`, within the
	// range `project:p1.report`, though it acts on the parent project.
	it("denies an action that is several elements of the grammar, though the joined path would lie within the range", async () => {
		const res = await request(app)
			.post("/verify")
			.set(
				"Authorization",
				`Bearer ${await tokenWith({ scope: "report.delete:project", authorization_details: [{ type: TYPE, path: "project:p1.report" }] })}`,
			)
			.send({ resource: "project:p1", action: "report.delete" });

		expect(res.status).toBe(403);
		expect(res.body.code).toBe("outside_delegation_range");
	});

	it("decides a token without a range as the policies alone do", async () => {
		const res = await verify(await tokenWith({}), "project:p2.report:r7");

		expect(res.status).toBe(200);
	});
});
