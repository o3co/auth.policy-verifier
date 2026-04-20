// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import type { Module } from "@o3co/auth.policy-verifier.core";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, builtinKeyResolversModule, createApp } from "#/index.mjs";

const JWT_SECRET = "test-secret";
const secretKey = new TextEncoder().encode(JWT_SECRET);

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().sign(secretKey);
}

// Minimal test module that registers factories for a scope collector and rule collector
const testModule: Module = {
	name: "test-module",
	async init(context) {
		context.attributeCollectorRegistry.register("TestScopeCollector", () => ({
			async collect(ctx) {
				const scopes = ((ctx.payload.scope as string) ?? "").split(" ");
				return new Map([["scopes", scopes]]);
			},
		}));
		context.ruleCollectorRegistry.register("TestScopeRuleCollector", () => ({
			async collect(ctx) {
				return [
					{
						ruleType: "scope",
						code: "invalid_scope",
						message: "Insufficient scope",
						verify(attributes) {
							const scopes = (attributes.get("scopes") as string[]) ?? [];
							return scopes.includes(`${ctx.action}:${ctx.resource.resourceType}`);
						},
					},
				];
			},
		}));
		context.resourceParserRegistry.register("SimpleParser", () => ({
			parse(raw: string) {
				return { raw, resourceType: raw, resourceId: undefined };
			},
		}));
	},
};

const testConfig = AppConfigSchema.parse({
	oauth: { jwt: { secret: JWT_SECRET, validate: true } },
	attribute: { collectors: [{ collector: "TestScopeCollector" }] },
	rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
	resource: { parser: "SimpleParser" },
});

describe("createApp", () => {
	it("creates an Express app that allows valid requests", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("denies requests with insufficient scope", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const token = await signToken({ scope: "write:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(403);
		expect(res.body.decision).toBe("deny");
	});

	it("throws if config references unregistered collector", async () => {
		const badConfig = AppConfigSchema.parse({
			oauth: { jwt: { secret: JWT_SECRET, validate: true } },
			attribute: { collectors: [{ collector: "NonExistent" }] },
			rule: { collectors: [] },
		});

		await expect(
			createApp({
				pathResolver: (s: string) => s,
				config: badConfig,
				modules: [testModule, builtinKeyResolversModule],
			}),
		).rejects.toThrow('Registry: "NonExistent" is not registered');
	});

	it("includes healthcheck endpoint", async () => {
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: testConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		const res = await request(app).get("/healthcheck");
		expect(res.status).toBe(200);
	});

	it("starts successfully and decodes tokens when validate=false with no key material", async () => {
		// validate=false + no secret/publicKey/jwksUri must not throw at startup
		const noKeyConfig = AppConfigSchema.parse({
			oauth: { jwt: { validate: false } },
			attribute: { collectors: [{ collector: "TestScopeCollector" }] },
			rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
			resource: { parser: "SimpleParser" },
		});

		const app = await createApp({
			pathResolver: (s: string) => s,
			config: noKeyConfig,
			modules: [testModule, builtinKeyResolversModule],
		});

		// Token is decoded (not verified) — use the same secret but validation is skipped
		const token = await signToken({ scope: "read:project" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});
});
