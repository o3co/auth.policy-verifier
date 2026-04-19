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

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().sign(secretKey);
}

// Config mirrors the structure of application.conf, using the same builtin registry keys.
// PayloadScopeCollector extracts scopes from the JWT "scope" claim.
// ResourceActionScopeRuleCollector requires scope "<action>:<resourceType>" to be present.
// DotNotationResourceParser is the default and matches the omitted resource.parser in application.conf.
const baseConfig = AppConfigSchema.parse({
	oauth: { jwt: { secret: JWT_SECRET, validate: true } },
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
