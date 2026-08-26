// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	type AttributeCollector,
	AttributePipeline,
	type Attributes,
	type CollectorContext,
	type ResourceParser,
	type Rule,
	type RuleCollector,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { exportSPKI, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { HS256KeyResolverFactory, RS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

const JWT_SECRET = "test-secret";
const hs256Key = await HS256KeyResolverFactory({ secret: JWT_SECRET });

/** Canonical issuer/audience this verifier deployment pins (RFC 9068 §4). */
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

/** Overrides for minting a token that deviates from what the verifier accepts. */
interface TokenOverrides {
	issuer?: string;
	audience?: string;
	typ?: string;
}

async function signHS256Token(
	payload: Record<string, unknown>,
	overrides: TokenOverrides = {},
): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: overrides.typ ?? "at+jwt" })
		.setIssuedAt()
		.setIssuer(overrides.issuer ?? ISSUER)
		.setAudience(overrides.audience ?? AUDIENCE)
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

function createTestApp(resourceParser?: ResourceParser, ruleCollectors?: RuleCollector[]) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: {
				validate: true,
				key: hs256Key.key,
				algorithms: hs256Key.algorithms,
				issuer: ISSUER,
				audience: AUDIENCE,
				tokenType: "at+jwt",
			},
			resourceParser: resourceParser ?? new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline(ruleCollectors ?? [new ResourceActionScopeRuleCollector()]),
		}),
	);
	return app;
}

describe("POST /verify", () => {
	const app = createTestApp();

	it("returns allow for valid token with matching scope", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("returns deny for valid token without matching scope", async () => {
		const token = await signHS256Token({ scope: "write:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_scope");
	});

	it("returns 401 when no Authorization header", async () => {
		const res = await request(app).post("/verify").send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("missing_token");
	});

	it("returns 401 for invalid JWT", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", "Bearer invalid.token.here")
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("accepts context in request body without error", async () => {
		const app = createTestApp();
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: { ip: "203.0.113.1" } });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("works without context (backward compatible)", async () => {
		const app = createTestApp();
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	// Verifies the end-to-end wiring: HTTP body.context → CollectorContext.requestContext →
	// project-specific AttributeCollector → Attributes → Rule.verify(attrs). This mirrors
	// the worked example in AGENTS.md (Core Vocabulary Scope > Writing Project-Specific
	// Attribute Collectors) and guards against silent regressions in the route's
	// requestContext plumbing.
	const ATTR_SUBSCRIBER_DID = "subscriberDid" as const;

	class SubscriberDidCollector implements AttributeCollector {
		async collect(context: CollectorContext): Promise<Attributes> {
			const attrs: Attributes = new Map();
			const v = context.requestContext?.subscriber_did;
			if (typeof v === "string" && v.length > 0) {
				attrs.set(ATTR_SUBSCRIBER_DID, v);
			}
			return attrs;
		}
	}

	class RequireSubscriberDidCollector implements RuleCollector {
		async collect(): Promise<Rule[]> {
			return [
				{
					ruleType: "subscriber_did",
					code: "missing_subscriber_did",
					message: "subscriber_did is required",
					verify: (attrs) => typeof attrs.get(ATTR_SUBSCRIBER_DID) === "string",
				},
			];
		}
	}

	function createAppWithSubscriberDid() {
		const app = express();
		app.use(
			createVerifyRouter({
				jwt: {
					validate: true,
					key: hs256Key.key,
					algorithms: hs256Key.algorithms,
					issuer: ISSUER,
					audience: AUDIENCE,
					tokenType: "at+jwt",
				},
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new SubscriberDidCollector()]),
				rulePipeline: new RulePipeline([new RequireSubscriberDidCollector()]),
			}),
		);
		return app;
	}

	it("routes body.context → requestContext → AttributeCollector → attrs (allow)", async () => {
		const app = createAppWithSubscriberDid();
		const token = await signHS256Token({});
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({
				resource: "project:1",
				action: "read",
				context: { subscriber_did: "did:dplaas:r1:org:alice" },
			});

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("routes body.context → requestContext → AttributeCollector → attrs (deny when absent)", async () => {
		const app = createAppWithSubscriberDid();
		const token = await signHS256Token({});
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("missing_subscriber_did");
	});

	it("returns 401 for expired JWT", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setExpirationTime("-1s")
			.sign(hs256Key.key as import("node:crypto").KeyObject);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});
});

describe("POST /verify with RS256", () => {
	it("returns 200 allow for valid RS256 token", async () => {
		const { privateKey, publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
		const publicKeyPem = await exportSPKI(publicKey as unknown as CryptoKey);
		const rs256Resolver = await RS256KeyResolverFactory({ publicKey: publicKeyPem });

		const app = express();
		app.use(
			createVerifyRouter({
				jwt: {
					validate: true,
					key: rs256Resolver.key,
					algorithms: rs256Resolver.algorithms,
					issuer: ISSUER,
					audience: AUDIENCE,
					tokenType: "at+jwt",
				},
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);

		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "RS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(privateKey as unknown as CryptoKey);

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("returns 401 for RS256 token signed with wrong key", async () => {
		const { publicKey } = await generateKeyPairAsync("rsa", { modulusLength: 2048 });
		const { privateKey: wrongPrivateKey } = await generateKeyPairAsync("rsa", {
			modulusLength: 2048,
		});
		const publicKeyPem = await exportSPKI(publicKey as unknown as CryptoKey);
		const rs256Resolver = await RS256KeyResolverFactory({ publicKey: publicKeyPem });

		const app = express();
		app.use(
			createVerifyRouter({
				jwt: {
					validate: true,
					key: rs256Resolver.key,
					algorithms: rs256Resolver.algorithms,
					issuer: ISSUER,
					audience: AUDIENCE,
					tokenType: "at+jwt",
				},
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);

		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "RS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(wrongPrivateKey as unknown as CryptoKey);

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});
});

describe("POST /verify — Bearer scheme validation (#17)", () => {
	const app = createTestApp();

	it("returns 401 with unsupported_scheme for Basic scheme", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Basic ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("unsupported_scheme");
	});

	it("returns 401 with unsupported_scheme when no space separator (no scheme)", async () => {
		const res = await request(app)
			.post("/verify")
			.set("Authorization", "tokenonly")
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("unsupported_scheme");
	});

	it("accepts bearer (lowercase) scheme — case-insensitive", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});
});

describe("POST /verify — scopeless JWT (DID grant) (#27, #104)", () => {
	const app = createTestApp();

	/** Rule collector standing in for a DID-grant pipeline: authorizes by `sub` prefix. */
	const didRuleCollector: RuleCollector = {
		async collect() {
			return [
				{
					ruleType: "did",
					code: "unknown_subject",
					message: "Subject is not a recognized DID",
					verify(attrs: Attributes) {
						return String(attrs.get("sub") ?? "").startsWith("did:example:");
					},
				},
			];
		},
	};

	const didAttributeCollector: AttributeCollector = {
		async collect(context: CollectorContext) {
			return new Map<string, unknown>([["sub", context.payload.sub]]);
		},
	};

	it("denies a scopeless token in a scope-only pipeline", async () => {
		// The scope rule is emitted regardless of the claim, so a token asserting no
		// capability fails it instead of dropping the group from AND-evaluation.
		const token = await signHS256Token({ sub: "did:example:123" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_scope");
	});

	it("still denies a scopeless token when the scope collector opts into scopeless: skip alone", async () => {
		// Skipping leaves the request with no applicable rule; the engine default-denies
		// rather than treating "nothing collected" as "nothing to enforce".
		const skipApp = createTestApp(undefined, [
			new ResourceActionScopeRuleCollector({ scopeless: "skip" }),
		]);
		const token = await signHS256Token({ sub: "did:example:123" });
		const res = await request(skipApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.code).toBe("no_applicable_rule");
	});

	it("allows a scopeless token when scopeless: skip is paired with an identity rule that passes", async () => {
		// The supported DID-grant wiring: another rule group carries the decision.
		const didApp = express();
		didApp.use(
			createVerifyRouter({
				jwt: { key: hs256Key.key, algorithms: hs256Key.algorithms, validate: true },
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([
					new PayloadScopeCollector(),
					didAttributeCollector,
				]),
				rulePipeline: new RulePipeline([
					new ResourceActionScopeRuleCollector({ scopeless: "skip" }),
					didRuleCollector,
				]),
			}),
		);

		const token = await signHS256Token({ sub: "did:example:123" });
		const res = await request(didApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("still denies when scope claim is present but does not match", async () => {
		const token = await signHS256Token({ sub: "did:example:123", scope: "write:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("invalid_scope");
	});
});

describe("POST /verify — request body validation (#18)", () => {
	const app = createTestApp();

	async function makeRequest(body: Record<string, unknown>) {
		const token = await signHS256Token({ scope: "read:project" });
		return request(app).post("/verify").set("Authorization", `Bearer ${token}`).send(body);
	}

	it("returns 400 with invalid_request when resource is missing", async () => {
		const res = await makeRequest({ action: "read" });
		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 with invalid_request when action is missing", async () => {
		const res = await makeRequest({ resource: "project:1" });
		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 with invalid_request when resource is empty string", async () => {
		const res = await makeRequest({ resource: "", action: "read" });
		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 with invalid_request when resource is a number", async () => {
		const res = await makeRequest({ resource: 42, action: "read" });
		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 with invalid_request when action is empty string", async () => {
		const res = await makeRequest({ resource: "project:1", action: "" });
		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});
});

describe("POST /verify — RFC 9068 §4 token validation (#105)", () => {
	const app = createTestApp();

	it("allows a token from the configured issuer and audience with typ at+jwt", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("rejects a token minted by a foreign issuer", async () => {
		const token = await signHS256Token({ scope: "read:project" }, { issuer: "https://evil.test" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("rejects a token minted for a different audience", async () => {
		const token = await signHS256Token(
			{ scope: "read:project" },
			{ audience: "https://other-service.test" },
		);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("rejects a token carrying no iss claim", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			.setAudience(AUDIENCE)
			.sign(hs256Key.key as import("node:crypto").KeyObject);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("rejects a token carrying no aud claim", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.sign(hs256Key.key as import("node:crypto").KeyObject);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	// The paired provider signs id_tokens, refresh tokens and logout tokens with the
	// same key as access tokens; only the typ header separates them.
	it.each(["id+jwt", "rt+jwt", "logout+jwt"])(
		"rejects a %s token signed with the same key",
		async (typ) => {
			const token = await signHS256Token({ scope: "read:project" }, { typ });
			const res = await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource: "project:1", action: "read" });

			expect(res.status).toBe(401);
			expect(res.body.code).toBe("invalid_token");
		},
	);

	it("rejects a token with no typ header", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(hs256Key.key as import("node:crypto").KeyObject);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("accepts the application/at+jwt spelling of the same media type", async () => {
		const token = await signHS256Token({ scope: "read:project" }, { typ: "application/at+jwt" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("accepts a token whose aud array contains the configured audience", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			.setIssuer(ISSUER)
			.setAudience(["https://other-service.test", AUDIENCE])
			.sign(hs256Key.key as import("node:crypto").KeyObject);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("refuses to build a verifying router without an issuer", () => {
		expect(() =>
			createVerifyRouter({
				jwt: {
					validate: true,
					key: hs256Key.key,
					algorithms: hs256Key.algorithms,
					audience: AUDIENCE,
					tokenType: "at+jwt",
				} as unknown as Parameters<typeof createVerifyRouter>[0]["jwt"],
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		).toThrow(/issuer/);
	});

	it("refuses to build a verifying router without an audience", () => {
		expect(() =>
			createVerifyRouter({
				jwt: {
					validate: true,
					key: hs256Key.key,
					algorithms: hs256Key.algorithms,
					issuer: ISSUER,
					tokenType: "at+jwt",
				} as unknown as Parameters<typeof createVerifyRouter>[0]["jwt"],
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		).toThrow(/audience/);
	});
});
