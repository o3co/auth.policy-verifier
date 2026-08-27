// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Smoke tests for the standalone template.
 *
 * These tests verify that the app created by the standalone template boots correctly
 * and that core HTTP endpoints respond as expected.
 *
 * The composition here intentionally mirrors main.mts — using builtinCollectorsModule
 * and registry keys that match application.conf — so that renames or interface changes
 * in the builtins package are caught here before reaching production.
 *
 * Note: ResourceActionPermissionRuleCollector is omitted from the smoke config because
 * it requires a permission store (e.g. StaticPermissionCollector) to grant any access.
 * The scope-based check via ResourceActionScopeRuleCollector is sufficient to exercise
 * the allow/deny paths in isolation.
 */
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import {
	AppConfigSchema,
	builtinKeyResolversModule,
	createApp,
} from "@o3co/auth.policy-verifier.server";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";

const JWT_SECRET = "standalone-smoke-secret";
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return (
		new SignJWT(payload)
			.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
			.setIssuedAt()
			// iat and exp are both mandatory now (#110).
			.setExpirationTime("1h")
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(secretKey)
	);
}

// Shared by every config below so a change to the jwt wire keys has one place
// to land rather than drifting between the base config and the variants.
const JWT_CONFIG = {
	secret: JWT_SECRET,
	mode: "verify",
	issuer: ISSUER,
	audience: AUDIENCE,
} as const;

// Config mirrors the structure of application.conf, using the same builtin registry keys.
// PayloadScopeCollector extracts scopes from the JWT "scope" claim.
// ResourceActionScopeRuleCollector requires scope "<action>:<resourceType>" to be present.
// DotNotationResourceParser is the default and matches the omitted resource.parser in application.conf.
const baseConfig = AppConfigSchema.parse({
	oauth: { jwt: JWT_CONFIG },
	attribute: {
		collectors: [
			{ collector: "PayloadScopeCollector" },
			{ collector: "PayloadSubjectIdCollector" },
		],
	},
	rule: {
		collectors: [{ collector: "ResourceActionScopeRuleCollector" }],
	},
	// resource.parser defaults to "DotNotationResourceParser" — matches application.conf omission
});

describe("standalone smoke", () => {
	it("GET /healthcheck returns 200", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		const res = await request(app).get("/healthcheck");
		expect(res.status).toBe(200);
	});

	it("POST /verify with sufficient scope returns 200 (allow)", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// PayloadScopeCollector extracts "read:document" from the JWT scope claim.
		// ResourceActionScopeRuleCollector requires scope "<action>:<resourceType>".
		// DotNotationResourceParser maps "document" → resourceType "document".
		const token = await signToken({ scope: "read:document" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("POST /verify with a scopeless token returns 403 (deny)", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// A validly-signed token carrying no scope claim asserts no capability, so a
		// scope-only pipeline must deny it rather than collect zero rules and allow.
		const token = await signToken({ sub: "user-1" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});

	it("POST /verify with an id_token signed by the same key returns 401", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// The paired provider signs id_tokens with the same key as access tokens;
		// only the typ header separates them.
		const token = await new SignJWT({ scope: "read:document" })
			.setProtectedHeader({ alg: "HS256", typ: "id+jwt" })
			.setIssuedAt()
			.setExpirationTime("1h")
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.sign(secretKey);
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(401);
		expect(res.body.code).toBe("invalid_token");
	});

	it("POST /verify/batch decides every entry in one round trip", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		const token = await signToken({ sub: "user-1", scope: "read:document" });
		const res = await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "document", action: "read" },
					{ resource: "document", action: "write" },
				],
			});

		expect(res.status).toBe(200);
		expect(res.body.decisions.map((d: { decision: string }) => d.decision)).toEqual([
			"allow",
			"deny",
		]);
		expect(res.body.decisions[0].subject).toBe("user-1");
	});

	it("POST /verify with a differently-cased scope returns 403 (deny)", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// Scope values are case-sensitive opaque strings (RFC 6749 §3.3), so
		// "read:DOCUMENT" must not satisfy the required "read:document".
		const token = await signToken({ scope: "read:DOCUMENT" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});

	it("POST /verify with a bare scope returns 403 unless the rewrite is opted into", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// A bare "document" is not rewritten to "read:document" by default.
		const token = await signToken({ scope: "document" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});

	it("POST /verify allows a bare scope once allowBareScopeRewrite is configured", async () => {
		// Proves the opt-in survives the config schema and reaches the collector,
		// which is the only path a deployment has to re-enable the old rewrite.
		const rewritingConfig = AppConfigSchema.parse({
			oauth: { jwt: JWT_CONFIG },
			attribute: { collectors: [{ collector: "PayloadScopeCollector" }] },
			rule: {
				collectors: [
					{ collector: "ResourceActionScopeRuleCollector", allowBareScopeRewrite: true },
				],
			},
		});
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: rewritingConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "document" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("POST /verify with insufficient scope returns 403 (deny)", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: baseConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
		});

		// Token has "write:document" but action is "read", so HasScope("read:document") fails.
		const token = await signToken({ scope: "write:document" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});
});
