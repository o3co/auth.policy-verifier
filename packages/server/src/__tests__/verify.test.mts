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
	readUntrustedRequestContext,
	type UntrustedRequestContext,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { exportSPKI, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { HS256KeyResolverFactory, RS256KeyResolverFactory } from "#/jwt/index.mjs";
import { createVerifyRouter, type VerifyRouterConfig } from "#/routes/verify.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
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
	return (
		new SignJWT(payload)
			.setProtectedHeader({ alg: "HS256", typ: overrides.typ ?? "at+jwt" })
			.setIssuedAt()
			// iat and exp are both mandatory now (#110): a token without them is
			// refused before any of the deviations these cases are about is reached.
			.setExpirationTime("1h")
			.setIssuer(overrides.issuer ?? ISSUER)
			.setAudience(overrides.audience ?? AUDIENCE)
			.sign(hs256Key.key as import("node:crypto").KeyObject)
	);
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
			const v = readUntrustedRequestContext(context.requestContext)?.subscriber_did;
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

	it("hands collectors the body context marked untrusted, not the raw object", async () => {
		// The body's `context` is whatever the caller typed. It must not arrive at a
		// collector shaped like the claim set next to it, or promoting
		// `requestContext.role` into an attribute reads like promoting `payload.sub`
		// and the caller has written its own authorization input.
		const seen: Array<UntrustedRequestContext | undefined> = [];
		const recordingCollector: AttributeCollector = {
			async collect(context: CollectorContext) {
				seen.push(context.requestContext);
				return new Map();
			},
		};
		const recordingApp = express();
		recordingApp.use(
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
				attributePipeline: new AttributePipeline([recordingCollector]),
				rulePipeline: new RulePipeline([]),
			}),
		);

		const token = await signHS256Token({});
		await request(recordingApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: { role: "admin" } });

		expect(seen).toHaveLength(1);
		// Sealed: nothing readable without the accessor, so a serializer walking
		// the collector context cannot copy the caller's payload out of it either.
		expect(Object.keys(seen[0] as object)).toEqual([]);
		expect(readUntrustedRequestContext(seen[0])).toEqual({ role: "admin" });
	});

	it("tells an omitted context apart from an empty one", async () => {
		const seen: Array<UntrustedRequestContext | undefined> = [];
		const recordingCollector: AttributeCollector = {
			async collect(context: CollectorContext) {
				seen.push(context.requestContext);
				return new Map();
			},
		};
		const recordingApp = express();
		recordingApp.use(
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
				attributePipeline: new AttributePipeline([recordingCollector]),
				rulePipeline: new RulePipeline([]),
			}),
		);

		const token = await signHS256Token({});
		await request(recordingApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });
		await request(recordingApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: {} });

		// An omitted context stays `undefined` instead of becoming an empty marked
		// record. The distinction is observable on the unwrapped record itself —
		// `undefined` versus `{}` — and not on a field read through it, since
		// `readUntrustedRequestContext(...)?.field` is `undefined` either way.
		expect(seen[0]).toBeUndefined();
		expect(readUntrustedRequestContext(seen[0])).toBeUndefined();
		expect(readUntrustedRequestContext(seen[1])).toEqual({});
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
			.setExpirationTime("1h")
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
			.setExpirationTime("1h")
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
				jwt: {
					validate: true,
					key: hs256Key.key,
					algorithms: hs256Key.algorithms,
					issuer: ISSUER,
					audience: AUDIENCE,
					tokenType: "at+jwt",
				},
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

describe("POST /verify — resource the parser refuses (#117)", () => {
	const app = createTestApp();

	async function makeRequest(body: Record<string, unknown>) {
		const token = await signHS256Token({ scope: "read:project" });
		return request(app).post("/verify").set("Authorization", `Bearer ${token}`).send(body);
	}

	// A resource string outside the parser's grammar is a malformed request, the
	// same class as a missing `action` — not a server fault. Answering 500 would
	// both mislead the caller and page the operator over somebody's typo.
	const refused = ["a..b", "a:1:2", ".project", "project.", "  project:1  ", "project : 1"];

	for (const resource of refused) {
		it(`returns 400 invalid_request for ${JSON.stringify(resource)}`, async () => {
			const res = await makeRequest({ resource, action: "read" });

			expect(res.status).toBe(400);
			expect(res.body.code).toBe("invalid_request");
			expect(res.body.decision).toBe("deny");
		});
	}

	it("names the offending resource string in the message", async () => {
		const res = await makeRequest({ resource: "a..b", action: "read" });

		expect(res.status).toBe(400);
		expect(res.body.message).toContain("a..b");
	});

	it("still answers 500 when the parser fails for an unrelated reason", async () => {
		// Only a ResourceParseError means "the caller's string is malformed".
		// Any other throw is a bug in the parser and must stay a 500, not be
		// re-labelled as the caller's fault.
		const brokenParser: ResourceParser = {
			parse() {
				throw new Error("parser store exploded");
			},
		};
		const brokenApp = createTestApp(brokenParser);
		const token = await signHS256Token({ scope: "read:project" });

		const res = await request(brokenApp)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(500);
		expect(res.body.code).toBe("internal_error");
	});

	it("refuses the resource before authenticating (#118)", async () => {
		// BREAKING in #118, and the reverse of what this pinned before: 400 now
		// outranks 401, because the body checks are bounded while verifying the
		// token is the half that can reach the network. The cost is that an
		// anonymous caller learns the grammar refused their string;
		// `http.callerAuth` is the gate for a deployment that must not disclose
		// even that. See the ordering paragraph on `createVerifyRouter`.
		const res = await request(app).post("/verify").send({ resource: "a..b", action: "read" });

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
			.setExpirationTime("1h")
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
			.setExpirationTime("1h")
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
			.setExpirationTime("1h")
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
			.setExpirationTime("1h")
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

	it("refuses to build a decode-only router without the acknowledgment (#106)", () => {
		// The double opt-in must hold at the server package's API boundary too:
		// wiring the router directly is not a way around it.
		expect(() =>
			createVerifyRouter({
				jwt: { validate: false } as unknown as Parameters<typeof createVerifyRouter>[0]["jwt"],
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		).toThrow(/allowInsecureDecode/);
	});
});

describe("POST /verify — decision contract (#124)", () => {
	const app = createTestApp();

	it("echoes the subject, resource and action the decision was made for", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			subject: "user-1",
			resource: "project:1",
			action: "read",
			decision: "allow",
		});
	});

	it("carries a structured reason on an allow", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.body.reason.groups).toEqual([
			{
				ruleType: "scope",
				passed: true,
				evaluated: [
					{
						code: "invalid_scope",
						message: "Token does not have required scope: read:project",
						passed: true,
					},
				],
				satisfiedBy: {
					code: "invalid_scope",
					message: "Token does not have required scope: read:project",
					passed: true,
				},
			},
		]);
	});

	it("carries a structured reason on a deny, naming the failing group", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "write:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body).toMatchObject({ decision: "deny", code: "invalid_scope" });
		expect(res.body.reason.groups).toEqual([
			{
				ruleType: "scope",
				passed: false,
				evaluated: [
					{
						code: "invalid_scope",
						message: "Token does not have required scope: read:project",
						passed: false,
					},
				],
			},
		]);
	});

	it("omits subject when the token carries no sub claim", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.subject).toBeUndefined();
	});

	it("omits subject when the sub claim is present but empty (#158)", async () => {
		// The audit line already treats `sub: ""` as no subject at all; the wire
		// response is the same value and must take the same disposition, or a
		// consumer reading `subject` sees an empty subject that the log says the
		// decision did not have. `subject` is optional on `DecisionResponse`, so
		// omitting it is what the published contract already promises.
		const token = await signHS256Token({ sub: "", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body).not.toHaveProperty("subject");
	});

	it("rejects an array as context on the single endpoint too", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: ["a"] });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("never takes the subject from the request body", async () => {
		// The token is the only authority on who is asking; accepting a body-supplied
		// subject would let any token holder ask for a decision about anyone else.
		// Since #118 the request is refused rather than silently stripped — a caller
		// that sent one was being told nothing while believing it had been honoured.
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", subject: "admin" });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("subject");
		expect(res.body.subject).toBeUndefined();
	});

	it("answers with the token's subject, never one the body could have named", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.body.subject).toBe("user-1");
	});
});

describe("POST /verify/batch (#124)", () => {
	const app = createTestApp();

	it("decides every entry in one round trip, preserving order", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "project:2", action: "write" },
					{ resource: "project:3", action: "read" },
				],
			});

		expect(res.status).toBe(200);
		expect(res.body.decisions).toHaveLength(3);
		expect(res.body.decisions.map((d: { decision: string }) => d.decision)).toEqual([
			"allow",
			"deny",
			"allow",
		]);
		expect(res.body.decisions.map((d: { resource: string }) => d.resource)).toEqual([
			"project:1",
			"project:2",
			"project:3",
		]);
	});

	it("answers 200 even when every entry is denied — the batch itself succeeded", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [{ resource: "project:1", action: "delete" }] });

		expect(res.status).toBe(200);
		expect(res.body.decisions[0].decision).toBe("deny");
		expect(res.body.decisions[0].reason.groups).toHaveLength(1);
	});

	it("passes each entry its own context", async () => {
		const contexts: Array<Record<string, unknown> | undefined> = [];
		const recordingCollector: AttributeCollector = {
			async collect(context: CollectorContext) {
				contexts.push(readUntrustedRequestContext(context.requestContext));
				return new Map();
			},
		};
		const recordingApp = express();
		recordingApp.use(
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
				attributePipeline: new AttributePipeline([new PayloadScopeCollector(), recordingCollector]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);

		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		await request(recordingApp)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read", context: { tenant: "a" } },
					{ resource: "project:2", action: "read", context: { tenant: "b" } },
				],
			});

		expect(contexts).toEqual([{ tenant: "a" }, { tenant: "b" }]);
	});

	it("returns 400 when an entry's context is an array", async () => {
		// `typeof [] === "object"`, so an array would otherwise reach
		// CollectorContext.requestContext as a shape no collector expects.
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [{ resource: "project:1", action: "read", context: ["a"] }] });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("context");
	});

	it("returns 400 when decisions is absent", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 when decisions is empty", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [] });

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
	});

	it("returns 400 naming the offending index when an entry is malformed", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [{ resource: "project:1", action: "read" }, { resource: "project:2" }],
			});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("decisions[1]");
	});

	it("returns 400 when the batch exceeds the configured cap", async () => {
		const cappedApp = express();
		cappedApp.use(
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
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
				maxBatchSize: 2,
			}),
		);

		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(cappedApp)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "project:2", action: "read" },
					{ resource: "project:3", action: "read" },
				],
			});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("2");
	});

	it("rejects the whole batch with 401 when the token does not verify", async () => {
		const token = await signHS256Token({ scope: "read:project" }, { issuer: "https://evil.test" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({ decisions: [{ resource: "project:1", action: "read" }] });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("returns 400 naming the index whose resource the parser refuses (#117)", async () => {
		const token = await signHS256Token({ sub: "user-1", scope: "read:project" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "a..b", action: "read" },
					{ resource: "project:3", action: "read" },
				],
			});

		expect(res.status).toBe(400);
		expect(res.body.code).toBe("invalid_request");
		expect(res.body.message).toContain("decisions[1]");
		// The whole batch is refused before any of it is decided, exactly as for
		// a structurally malformed entry — not a partial answer.
		expect(res.body.decisions).toBeUndefined();
	});
});

describe("createVerifyRouter — maxBatchSize, one reader at both boundaries (#157)", () => {
	// The router is the hand-built boundary for `verify.maxBatchSize`: `createApp`
	// forwards whatever a config object carries there, so it must refuse the same
	// values `AppConfigSchema` refuses, in the same words. It used to refuse
	// nothing — `config.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE` read `null` as
	// "unset" (a 50-entry cap where the schema refused to boot) and let a `0`
	// through as a cap that rejects every batch there is.
	const buildRouter = (maxBatchSize: unknown) => () =>
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
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			maxBatchSize,
		} as VerifyRouterConfig);

	/** The message one boundary refused with, or `undefined` when it accepted the value. */
	const refusal = (act: () => unknown): string | undefined => {
		try {
			act();
			return undefined;
		} catch (cause) {
			return (cause as Error).message;
		}
	};

	const schemaRefusal = (maxBatchSize: unknown): string | undefined => {
		const result = AppConfigSchema.safeParse({
			oauth: {
				jwt: {
					algorithm: "HS256",
					secret: JWT_SECRET,
					mode: "verify",
					issuer: ISSUER,
					audience: AUDIENCE,
				},
			},
			attribute: { collectors: [] },
			rule: { collectors: [] },
			verify: { maxBatchSize },
		});
		return result.success
			? undefined
			: result.error.issues.find((issue) => issue.path.at(-1) === "maxBatchSize")?.message;
	};

	it.each([
		["zero — a cap that rejects every batch", 0],
		["a negative cap", -1],
		["a fractional cap", 1.5],
		["true", true],
		["false", false],
		["null", null],
		["an empty string", ""],
		["a non-numeric string", "abc"],
	])("refuses %s at router construction, in the schema's wording", (_label, maxBatchSize) => {
		const fromRouter = refusal(buildRouter(maxBatchSize));
		expect(fromRouter).toBeDefined();
		expect(schemaRefusal(maxBatchSize)).toBe(fromRouter);
	});

	it("takes the string a hand-built env config carries", () => {
		expect(refusal(buildRouter("25"))).toBeUndefined();
	});

	it("defaults when the cap is absent", () => {
		expect(refusal(buildRouter(undefined))).toBeUndefined();
	});
});

describe("createVerifyRouter — a collector that runs out of time denies (#115)", () => {
	/** Stalls only for the action named, so one batch can mix stalled and decided entries. */
	const stallingOn = (action: string): AttributeCollector => ({
		collect: (context: CollectorContext) =>
			context.action === action
				? new Promise<Attributes>(() => {})
				: Promise.resolve(new Map<string, unknown>([["scopes", ["read:project"]]])),
	});

	const stalledApp = () => {
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
				// Bounds low enough that the stall is answered well inside the
				// test's own timeout.
				attributePipeline: new AttributePipeline([stallingOn("stall")], {
					collectorTimeoutMs: 20,
					deadlineMs: 50,
				}),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);
		return app;
	};

	it("answers 403 with a collector_timeout deny", async () => {
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(stalledApp())
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "stall" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
		expect(res.body.code).toBe("collector_timeout");
		// No group was evaluated, and the reason says so rather than inventing one.
		expect(res.body.reason).toEqual({ groups: [] });
		// The message reaches the caller, so it names no collector and no bound.
		expect(res.body.message).not.toMatch(/collector|ms/i);
	});

	it.each([
		[
			"a malformed body, unauthenticated",
			(app: express.Express) => request(app).post("/verify").send({ resource: "project:1" }),
			400,
			"invalid_request",
		],
		[
			"a well-formed body with no token",
			(app: express.Express) =>
				request(app).post("/verify").send({ resource: "project:1", action: "stall" }),
			401,
			"missing_token",
		],
	])(
		"answers %s before any collector runs, rather than spending the budget on it",
		async (_label, send, status, code) => {
			// Ordering, pinned rather than read. #118 put body validation ahead of
			// the token, and both sit ahead of `decide` — so an unauthenticated
			// caller cannot make the verifier hold a collector budget open. If a
			// later change moved collection ahead of either gate, this case would
			// come back `403 collector_timeout` (and take the full budget doing
			// it) instead of the refusal it asserts.
			const res = await send(stalledApp());

			expect(res.status).toBe(status);
			expect(res.body.code).toBe(code);
			expect(res.body.code).not.toBe("collector_timeout");
		},
	);

	it("denies only the batch entry that stalled, and decides the rest", async () => {
		// The stall is per decision, not per request: a batch is many decisions,
		// and one of them running out of time must not refuse the others or turn
		// the whole batch into a 500.
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(stalledApp())
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "project:2", action: "stall" },
					{ resource: "project:3", action: "read" },
				],
			});

		expect(res.status).toBe(200);
		expect(res.body.decisions.map((d: { decision: string }) => d.decision)).toEqual([
			"allow",
			"deny",
			"allow",
		]);
		expect(res.body.decisions[1].code).toBe("collector_timeout");
	});
});
