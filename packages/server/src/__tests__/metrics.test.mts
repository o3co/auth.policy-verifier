// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * `/metrics` and the decision counters (#111).
 *
 * Two things are under test here and the second matters as much as the first.
 *
 * 1. The series exist and say what they should: allow/deny rate, which rule
 *    denied, decision latency, request latency, Node process defaults.
 * 2. Every label is BOUNDED. `resource` and `action` come from the request
 *    body and are unbounded by construction, so they must never appear as
 *    labels; `method` and the route come off the wire and are collapsed; the
 *    deny `code` comes from a rule implementation and is capped. An unbounded
 *    label mints one time series per distinct value, which is how a metrics
 *    endpoint takes down the monitoring meant to watch it — and none of these
 *    requires access to `/metrics` to reach.
 *
 * The shape mirrors auth.provider's metrics (39767d52) so one Prometheus job
 * and one dashboard convention serve the whole stack.
 */
import { request as httpRequest } from "node:http";
import type { Module } from "@o3co/auth.policy-verifier.core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { AppConfigSchema, builtinKeyResolversModule, createApp } from "#/index.mjs";
import { createMetrics, MAX_DENY_CODE_LABELS } from "#/observability/metrics.mjs";

const JWT_SECRET = "metrics-test-secret";
const secretKey = new TextEncoder().encode(JWT_SECRET);
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(secretKey);
}

/** Registers a scope rule whose `code` is a constant, as every builtin's is. */
const testModule: Module = {
	name: "metrics-test-module",
	async init(context) {
		context.attributeCollectorRegistry.register("TestScopeCollector", () => ({
			async collect(ctx) {
				return new Map([["scopes", ((ctx.payload.scope as string) ?? "").split(" ")]]);
			},
		}));
		context.ruleCollectorRegistry.register("TestScopeRuleCollector", () => ({
			async collect(ctx) {
				return [
					{
						ruleType: "scope",
						code: "invalid_scope",
						message: "Insufficient scope",
						verify(attrs) {
							const scopes = (attrs.get("scopes") as string[]) ?? [];
							return scopes.includes(`${ctx.action}:${ctx.resource.resourceType}`);
						},
					},
				];
			},
		}));
		context.resourceParserRegistry.register("SimpleParser", () => ({
			parse: (raw: string) => ({ raw, resourceType: raw, resourceId: undefined }),
		}));
	},
};

function configWith(overrides: Record<string, unknown> = {}) {
	return AppConfigSchema.parse({
		oauth: { jwt: { secret: JWT_SECRET, mode: "verify", issuer: ISSUER, audience: AUDIENCE } },
		attribute: { collectors: [{ collector: "TestScopeCollector" }] },
		rule: { collectors: [{ collector: "TestScopeRuleCollector" }] },
		resource: { parser: "SimpleParser" },
		...overrides,
	});
}

async function buildApp(overrides: Record<string, unknown> = {}) {
	return createApp({
		pathResolver: (s: string) => s,
		config: configWith(overrides),
		modules: [testModule, builtinKeyResolversModule],
	});
}

/** Metrics mounted on a bare express app, for the label tests that need arbitrary routes. */
function bareApp() {
	const metrics = createMetrics();
	const app = express();
	app.use(metrics.middleware);
	app.use(metrics.router);

	const api = express.Router();
	api.get("/widgets/:id", (_req, res) => {
		res.status(200).json({ ok: true });
	});
	app.use("/api", api);
	return { app, metrics };
}

describe("GET /metrics", () => {
	it("serves the Prometheus text exposition format", async () => {
		const res = await request(await buildApp()).get("/metrics");

		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toContain("text/plain");
		// A scrape answered from a cache reports the service healthy for exactly
		// as long as the cache lives.
		expect(res.headers["cache-control"]).toBe("no-store");
	});

	it("publishes the Node process defaults under a service-specific prefix", async () => {
		const res = await request(await buildApp()).get("/metrics");

		expect(res.text).toContain("auth_policy_verifier_process_cpu_user_seconds_total");
	});

	it("publishes the decision series even before any decision has been made", async () => {
		// A counter that only appears after the first event makes a dashboard
		// panel read "no data" instead of zero.
		const res = await request(await buildApp()).get("/metrics");

		expect(res.text).toContain("auth_decisions_total");
		expect(res.text).toContain("auth_denials_total");
		expect(res.text).toContain("auth_decision_duration_seconds");
		expect(res.text).toContain("http_request_duration_seconds");
	});
});

describe("decision counters", () => {
	it("counts decisions by outcome", async () => {
		const app = await buildApp();
		const token = await signToken({ sub: "user-1", scope: "read:project" });
		const decide = (resource: string) =>
			request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource, action: "read" });

		await decide("project");
		await decide("project");
		await decide("secret");

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('auth_decisions_total{decision="allow"} 2');
		expect(res.text).toContain('auth_decisions_total{decision="deny"} 1');
	});

	it("counts denials by the code of the rule that refused", async () => {
		const app = await buildApp();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "secret", action: "read" });

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('auth_denials_total{code="invalid_scope"} 1');
	});

	it("counts every entry of a batch, not the request", async () => {
		// One `/verify/batch` call is up to `verify.maxBatchSize` decisions; a
		// per-request counter would understate the decision rate by that factor.
		const app = await buildApp();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(app)
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project", action: "read" },
					{ resource: "project", action: "read" },
					{ resource: "secret", action: "read" },
				],
			});

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('auth_decisions_total{decision="allow"} 2');
		expect(res.text).toContain('auth_decisions_total{decision="deny"} 1');
	});

	it("records decision latency separately from request latency", async () => {
		const app = await buildApp();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('auth_decision_duration_seconds_count{decision="allow"} 1');
	});
});

describe("label bounding: resource and action never become labels", () => {
	it("keeps the caller's resource and action out of every series", async () => {
		// These are read straight from the request body. One series per distinct
		// resource id is an unbounded label set that any caller can drive, and
		// nothing about it requires reaching /metrics.
		const app = await buildApp();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		for (const id of ["alpha-0001", "alpha-0002", "alpha-0003"]) {
			await request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource: id, action: `probe-${id}` });
		}

		const res = await request(app).get("/metrics");
		expect(res.text).not.toContain("alpha-0001");
		expect(res.text).not.toContain("alpha-0003");
		expect(res.text).not.toContain("resource=");
		expect(res.text).not.toContain("action=");
		// The decisions were still counted — bounding is not dropping.
		expect(res.text).toContain('auth_decisions_total{decision="deny"} 3');
	});

	it("keeps the subject out of every series too", async () => {
		// `sub` belongs on the audit line, where high cardinality is the point.
		// As a label it is one series per user.
		const app = await buildApp();
		const token = await signToken({ sub: "user-cardinality-bomb", scope: "read:project" });

		await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const res = await request(app).get("/metrics");
		expect(res.text).not.toContain("user-cardinality-bomb");
	});
});

describe("label bounding: deny codes", () => {
	it("collapses deny codes into `other` past the cap", async () => {
		// `Rule.code` is an interface field and rules are built per request, so a
		// third-party rule collector is one edit away from a code derived from
		// the resource it was asked about.
		const { app, metrics } = bareApp();
		for (let i = 0; i < MAX_DENY_CODE_LABELS + 5; i += 1) {
			metrics.decisions.observe({ decision: "deny", code: `code_${i}`, durationSeconds: 0.001 });
		}

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('auth_denials_total{code="code_0"} 1');
		expect(res.text).toContain(`auth_denials_total{code="other"} 5`);
		expect(res.text).not.toContain(`code_${MAX_DENY_CODE_LABELS + 1}`);
	});
});

describe("label bounding: method and route", () => {
	it("labels by the route pattern, not the URL", async () => {
		const { app } = bareApp();
		for (const id of ["1", "2", "3"]) {
			await request(app).get(`/api/widgets/${id}`);
		}

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('route="/api/widgets/:id"');
		expect(res.text).not.toContain('route="/api/widgets/1"');
	});

	it("collapses unmatched requests into a single bucket", async () => {
		const { app } = bareApp();
		await request(app).get(`/nope/${"x".repeat(50)}`);

		const res = await request(app).get("/metrics");
		expect(res.text).toContain('route="unmatched"');
		expect(res.text).not.toContain("xxxxx");
	});

	it("collapses methods outside the allowlist into one label", async () => {
		// Node's parser hands the server every method llhttp knows, which is far
		// more than the nine this service can serve — WebDAV's MKCOL and PROPFIND,
		// caching proxies' PURGE, and more. Each one that reached a label would
		// mint a fresh histogram child carrying every bucket, and none of it needs
		// access to /metrics. Sent over a real socket because supertest cannot
		// express a non-standard method.
		const { app } = bareApp();
		const server = app.listen(0);
		const port = (server.address() as { port: number }).port;
		try {
			for (const method of ["PURGE", "MKCOL", "PROPFIND"]) {
				await new Promise<void>((resolve) => {
					const req = httpRequest(
						{ host: "127.0.0.1", port, path: "/api/widgets/1", method },
						(r) => {
							r.resume();
							r.once("end", resolve);
						},
					);
					req.once("error", () => resolve());
					req.end();
				});
			}

			const res = await request(app).get("/metrics");
			expect(res.text).toContain('method="other"');
			expect(res.text).not.toContain('method="PURGE"');
			expect(res.text).not.toContain('method="MKCOL"');
			expect(res.text).not.toContain('method="PROPFIND"');
		} finally {
			server.close();
		}
	});

	it("times requests that never reach a route, including rejected callers", async () => {
		const app = await buildApp({
			http: { hostname: "127.0.0.1", port: 3000, pathPrefix: "", callerAuth: { token: "s3cret" } },
		});

		const rejected = await request(app)
			.post("/verify")
			.send({ resource: "project", action: "read" });

		expect(rejected.status).toBe(401);
		const res = await request(app).get("/metrics");
		// A surge of caller-auth rejections is precisely what these series exist
		// to show, so the middleware sits ahead of the gate.
		expect(res.text).toContain('status="401"');
	});
});

describe("/metrics and caller authentication (#108)", () => {
	const gated = {
		http: { hostname: "127.0.0.1", port: 3000, pathPrefix: "", callerAuth: { token: "s3cret" } },
	};

	it("stays scrapable when the decision endpoints are gated on a caller credential", async () => {
		// Prometheus scrape_configs carry `authorization` / `basic_auth` / `oauth2`
		// and no arbitrary header, so gating /metrics on `x-caller-token` would
		// make it unscrapable by a stock scraper — and the workaround would be to
		// hand the credential that authorizes DECISIONS to the monitoring system.
		// The endpoint publishes counts and latencies with bounded labels and no
		// decision content, so the bind address is the boundary instead.
		const app = await buildApp(gated);

		const metrics = await request(app).get("/metrics");
		expect(metrics.status).toBe(200);
	});

	it("still gates the decision endpoints", async () => {
		const app = await buildApp(gated);

		const denied = await request(app).post("/verify").send({ resource: "project", action: "read" });
		expect(denied.status).toBe(401);
		expect(denied.body.code).toBe("caller_unauthenticated");
	});

	it("serves /metrics under the configured path prefix", async () => {
		const app = await buildApp({ http: { hostname: "127.0.0.1", port: 3000, pathPrefix: "/pdp" } });

		expect((await request(app).get("/pdp/metrics")).status).toBe(200);
		expect((await request(app).get("/metrics")).status).toBe(404);
	});
});
