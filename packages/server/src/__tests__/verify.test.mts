// Copyright 2026 1o1 Co. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	RequestContextCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	AttributePipeline,
	type ResourceParser,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { exportSPKI, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createKeyResolver } from "#/jwt/createKeyResolver.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

const generateKeyPairAsync = promisify(generateKeyPair);

const JWT_SECRET = "test-secret";
const hs256Key = await createKeyResolver({
	algorithm: "HS256",
	secret: JWT_SECRET,
	validate: true,
});

async function signHS256Token(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

function createTestApp(resourceParser?: ResourceParser) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: { key: hs256Key.key, algorithms: hs256Key.algorithms, validate: true },
			resourceParser: resourceParser ?? new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
		}),
	);
	return app;
}

function createTestAppWithContext() {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: { key: hs256Key.key, algorithms: hs256Key.algorithms, validate: true },
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([
				new PayloadScopeCollector(),
				new RequestContextCollector(),
			]),
			rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
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
		const app = createTestAppWithContext();
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read", context: { ip: "203.0.113.1" } });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("works without context (backward compatible)", async () => {
		const app = createTestAppWithContext();
		const token = await signHS256Token({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project:1", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("returns 401 for expired JWT", async () => {
		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt()
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
		const rs256Resolver = await createKeyResolver({
			algorithm: "RS256",
			publicKey: publicKeyPem,
			validate: true,
		});

		const app = express();
		app.use(
			createVerifyRouter({
				jwt: { key: rs256Resolver.key, algorithms: rs256Resolver.algorithms, validate: true },
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);

		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "RS256" })
			.setIssuedAt()
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
		const rs256Resolver = await createKeyResolver({
			algorithm: "RS256",
			publicKey: publicKeyPem,
			validate: true,
		});

		const app = express();
		app.use(
			createVerifyRouter({
				jwt: { key: rs256Resolver.key, algorithms: rs256Resolver.algorithms, validate: true },
				resourceParser: new DotNotationResourceParser(),
				attributePipeline: new AttributePipeline([new PayloadScopeCollector()]),
				rulePipeline: new RulePipeline([new ResourceActionScopeRuleCollector()]),
			}),
		);

		const token = await new SignJWT({ scope: "read:project" })
			.setProtectedHeader({ alg: "RS256" })
			.setIssuedAt()
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

describe("POST /verify — scopeless JWT (DID grant) (#27)", () => {
	const app = createTestApp();

	it("returns allow for valid token without scope claim", async () => {
		const token = await signHS256Token({ sub: "did:example:123" });
		const res = await request(app)
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
