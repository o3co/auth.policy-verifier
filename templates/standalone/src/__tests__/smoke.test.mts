// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Smoke tests for the standalone template.
 *
 * These tests boot the app from `config/application.conf` — the file the image
 * ships and an operator deploys — read through `loadAppConfig`, the same
 * function `main.mts` calls. Nothing here restates the policy: the thing under
 * test is the thing that ships.
 *
 * That is the point of #113. The suite used to assemble its own config, minus
 * the one collector that made the shipped file deny every request, and stayed
 * green while the product was non-functional. A config the tests hand-write can
 * agree with `application.conf` only by vigilance, and it stopped agreeing.
 *
 * The three values the file deliberately does not carry — the HS256 secret, the
 * issuer and the audience — come from the environment here exactly as they do
 * in a deployment. A credential must never be written in a config file, so
 * supplying them is loading the shipped config, not editing it.
 */
import { fileURLToPath } from "node:url";
import { builtinCollectorsModule } from "@o3co/auth.policy-verifier.builtins";
import { consoleLogger } from "@o3co/auth.policy-verifier.core";
import type { AppConfig } from "@o3co/auth.policy-verifier.server";
import { builtinKeyResolversModule, createApp } from "@o3co/auth.policy-verifier.server";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { loadAppConfig } from "../loadConfig.js";

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

const configDirPath = fileURLToPath(new URL("../../config/", import.meta.url));

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

/** The three values `application.conf` leaves to the deployment. */
const DEPLOYMENT_ENV = {
	OAUTH_JWT_SECRET: JWT_SECRET,
	OAUTH_JWT_ISSUER: ISSUER,
	OAUTH_JWT_AUDIENCE: AUDIENCE,
} as const;

/**
 * The shipped config, loaded the way the container loads it: the development
 * overlay resolved against `config/application.conf`, with the deployment's
 * three values in the environment.
 *
 * `process.env` is process-wide, and a test file does not own it. So each
 * variable's prior value is **restored**, not deleted — and "was absent" is
 * restored as absent rather than as `""`, which is a different state this very
 * config distinguishes (an exported-empty credential is refused rather than read
 * as "unset"). Deleting unconditionally would hand any file sharing the worker a
 * value this one happened to clear.
 *
 * The window is nil as well as tidy: every step here is synchronous —
 * `loadAppConfig` parses and validates without awaiting — and this runs at module
 * scope, so no other file's code can be scheduled between the assignment and the
 * restore.
 */
function loadShippedConfig(): AppConfig {
	const saved: Array<[key: string, previous: string | undefined]> = Object.keys(DEPLOYMENT_ENV).map(
		(key) => [key, process.env[key]],
	);
	Object.assign(process.env, DEPLOYMENT_ENV);
	try {
		return loadAppConfig(configDirPath, "development");
	} finally {
		for (const [key, previous] of saved) {
			if (previous === undefined) delete process.env[key];
			else process.env[key] = previous;
		}
	}
}

const shippedConfig = loadShippedConfig();

/** The composition `main.mts` builds, over whichever config is handed in. */
function createShippedApp(config: AppConfig = shippedConfig) {
	return createApp({
		pathResolver: (s: string) => s,
		config,
		modules: [builtinCollectorsModule, builtinKeyResolversModule],
	});
}

describe("standalone smoke", () => {
	it("GET /_healthcheck returns 200", async () => {
		// The liveness path the Dockerfile's HEALTHCHECK probes, and the one every
		// component of the stack answers on (o3co/auth.provider#293).
		const app = await createShippedApp();

		const res = await request(app).get("/_healthcheck");
		expect(res.status).toBe(200);
	});

	it("GET /healthcheck returns 200 as a compatibility alias", async () => {
		// The path this image probed before; a probe config that still names it
		// must keep working.
		const app = await createShippedApp();

		const res = await request(app).get("/healthcheck");
		expect(res.status).toBe(200);
	});

	it("POST /verify with sufficient scope returns 200 (allow)", async () => {
		const app = await createShippedApp();

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
		const app = await createShippedApp();

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
		const app = await createShippedApp();

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
		const app = await createShippedApp();

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
		const app = await createShippedApp();

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
		const app = await createShippedApp();

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
		// The one config in this file that is deliberately NOT the shipped one:
		// it exercises the opt-in application.conf documents in a comment beside
		// the collector, which is the only path a deployment has to re-enable the
		// old rewrite. It is derived from the shipped config rather than written
		// out, so the single key under test is the single thing that differs.
		const rewritingConfig: AppConfig = {
			...shippedConfig,
			rule: {
				...shippedConfig.rule,
				collectors: [
					{ collector: "ResourceActionScopeRuleCollector", allowBareScopeRewrite: true },
				],
			},
		};
		const app = await createShippedApp(rewritingConfig);

		const token = await signToken({ scope: "document" });
		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		expect(res.status).toBe(200);
		expect(res.body.decision).toBe("allow");
	});

	it("POST /verify with insufficient scope returns 403 (deny)", async () => {
		const app = await createShippedApp();

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

/*
 * #111. The template is the deployable shape, so these assert what an operator
 * of *this* composition actually gets — not what the library can be wired to do.
 */
describe("standalone observability", () => {
	it("GET /metrics serves the Prometheus text format with the decision counters", async () => {
		const app = await createShippedApp();

		const token = await signToken({ sub: "user-1", scope: "read:document" });
		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "document", action: "read" });

		const res = await request(app).get("/metrics");
		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toContain("text/plain");
		expect(res.text).toContain('auth_decisions_total{decision="allow"} 1');
		expect(res.text).toContain("auth_policy_verifier_process_cpu_user_seconds_total");
	});

	it("emits the per-decision audit line through the injected logger", async () => {
		// main.mts injects pino here; a capturing stand-in proves the line reaches
		// whatever the composition root wired, at the level `logging.level` gates.
		const lines: Array<{ obj: Record<string, unknown>; msg?: string }> = [];
		const app = await createApp({
			pathResolver: (s: string) => s,
			config: shippedConfig,
			modules: [builtinCollectorsModule, builtinKeyResolversModule],
			logger: {
				...consoleLogger,
				info(obj: Record<string, unknown> | string, msg?: string) {
					if (typeof obj === "object") lines.push({ obj, msg });
				},
			},
		});

		const token = await signToken({ sub: "user-1", scope: "read:document" });
		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("x-request-id", "trace-1")
			.send({ resource: "document:9", action: "read" });

		const decision = lines.find((l) => l.msg === "decision");
		expect(decision?.obj).toMatchObject({
			sub: "user-1",
			resource: "document:9",
			action: "read",
			decision: "allow",
			requestId: "trace-1",
		});
	});
});
