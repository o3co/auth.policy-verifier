// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Per-decision audit logging for the verify router (#111).
 *
 * #107 gave the router failure events. Nothing was emitted on the path that
 * actually decides, so the one question an authorization service exists to
 * answer after the fact — "why was this request denied?" — had no answer in
 * the service's own output. `x-request-id` was read and handed to collectors
 * but never emitted, so a decision could not even be correlated with the
 * caller's trace.
 *
 * The router now emits one `decision` event per decision, at info, carrying
 * who / what / which rule / how long. The level is the switch: `logging.level`
 * above info turns the stream off wholesale.
 *
 * The other half of these tests is what the line must NOT carry. A decision
 * log is written on every request, including the successful ones, and shipped
 * to an aggregator that is not the security boundary the token is — so the
 * raw bearer token and the full claim set stay out of it, and the caller's
 * `context` object (free-form, caller-supplied, and the natural place for
 * request payloads to end up) stays out with them.
 */
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	PayloadSubjectIdCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	AttributePipeline,
	type EventLogger,
	type Rule,
	type RuleCollector,
	RulePipeline,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { HS256KeyResolverFactory, type VerifyRouterJwtConfig } from "#/jwt/index.mjs";
import { createVerifyRouter } from "#/routes/verify.mjs";

const JWT_SECRET = "test-secret";
const hs256Key = await HS256KeyResolverFactory({ secret: JWT_SECRET });
const ISSUER = "https://issuer.test";
const AUDIENCE = "https://api.test";

interface CapturedEvent {
	level: "info" | "warn" | "error";
	obj: Record<string, unknown>;
	msg: string;
}

function captureEvents(): { events: CapturedEvent[]; logger: EventLogger } {
	const events: CapturedEvent[] = [];
	return {
		events,
		logger: {
			info(obj, msg) {
				events.push({ level: "info", obj, msg });
			},
			warn(obj, msg) {
				events.push({ level: "warn", obj, msg });
			},
			error(obj, msg) {
				events.push({ level: "error", obj, msg });
			},
		},
	};
}

const decisionsOf = (events: CapturedEvent[]) => events.filter((e) => e.msg === "decision");

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

const verifyingJwt: VerifyRouterJwtConfig = {
	validate: true,
	key: hs256Key.key,
	algorithms: hs256Key.algorithms,
	issuer: ISSUER,
	audience: AUDIENCE,
	tokenType: "at+jwt",
};

function createTestApp(overrides: { logger?: EventLogger; ruleCollectors?: RuleCollector[] } = {}) {
	const app = express();
	app.use(
		createVerifyRouter({
			jwt: verifyingJwt,
			logger: overrides.logger,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline([
				new PayloadScopeCollector(),
				new PayloadSubjectIdCollector(),
			]),
			rulePipeline: new RulePipeline(
				overrides.ruleCollectors ?? [new ResourceActionScopeRuleCollector()],
			),
		}),
	);
	return app;
}

describe("per-decision audit log", () => {
	it("emits one info `decision` event naming subject, resource, action and request id", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		const res = await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.set("x-request-id", "req-42")
			.send({ resource: "project:7", action: "read" });

		expect(res.status).toBe(200);
		const decisions = decisionsOf(events);
		expect(decisions).toHaveLength(1);
		expect(decisions[0].level).toBe("info");
		expect(decisions[0].obj).toMatchObject({
			sub: "user-1",
			resource: "project:7",
			action: "read",
			decision: "allow",
			requestId: "req-42",
		});
	});

	it("names the rule that satisfied each group on an allow (#135 satisfiedBy)", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const [decision] = decisionsOf(events);
		// `satisfiedBy` is the pass-side answer to "which rule decided". A group
		// is an OR that stops at its first passing rule, so this is that rule —
		// not merely the last thing that ran.
		expect(decision.obj.satisfiedBy).toEqual([{ ruleType: "scope", code: "invalid_scope" }]);
		expect(decision.obj.deniedBy).toBeUndefined();
	});

	it("names the failing group and every alternative it refused on a deny", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:other" });

		const res = await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(403);
		const [decision] = decisionsOf(events);
		expect(decision.level).toBe("info");
		expect(decision.obj).toMatchObject({
			decision: "deny",
			code: "invalid_scope",
			deniedBy: { ruleType: "scope", refused: ["invalid_scope"] },
		});
		expect(decision.obj.satisfiedBy).toBeUndefined();
	});

	it("reports the deny of a request that collected no rule at all", async () => {
		const { events, logger } = captureEvents();
		const emptyCollector: RuleCollector = {
			async collect(): Promise<Rule[]> {
				return [];
			},
		};
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		const res = await request(createTestApp({ logger, ruleCollectors: [emptyCollector] }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		expect(res.status).toBe(403);
		const [decision] = decisionsOf(events);
		// No group ran, so there is no group to blame — the code is the whole
		// answer, and inventing a `deniedBy` would name a rule that never existed.
		expect(decision.obj).toMatchObject({ decision: "deny", code: "no_applicable_rule" });
		expect(decision.obj.deniedBy).toBeUndefined();
	});

	it("records how long the decision took", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const [decision] = decisionsOf(events);
		expect(typeof decision.obj.durationMs).toBe("number");
		expect(decision.obj.durationMs as number).toBeGreaterThanOrEqual(0);
	});

	it("omits sub and requestId rather than emitting empty ones", async () => {
		// A token with no `sub` is legitimate (client-credentials), and most
		// callers send no `x-request-id`. `sub: ""` in an audit log is worse than
		// no key: it reads as a subject that exists.
		const { events, logger } = captureEvents();
		const token = await signToken({ scope: "read:project" });

		await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const [decision] = decisionsOf(events);
		expect(decision.obj).not.toHaveProperty("sub");
		expect(decision.obj).not.toHaveProperty("requestId");
	});

	it("emits one line per entry of a batch, each naming its own resource", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		const res = await request(createTestApp({ logger }))
			.post("/verify/batch")
			.set("Authorization", `Bearer ${token}`)
			.send({
				decisions: [
					{ resource: "project:1", action: "read" },
					{ resource: "secret:1", action: "read" },
				],
			});

		expect(res.status).toBe(200);
		const decisions = decisionsOf(events);
		expect(decisions).toHaveLength(2);
		expect(decisions.map((d) => [d.obj.resource, d.obj.decision])).toEqual([
			["project:1", "allow"],
			["secret:1", "deny"],
		]);
	});

	it("falls back to the console-backed logger when none is injected", async () => {
		const spy = vi.spyOn(console, "info").mockImplementation(() => {});
		try {
			const token = await signToken({ sub: "user-1", scope: "read:project" });

			await request(createTestApp())
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource: "project", action: "read" });

			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({ decision: "allow", resource: "project" }),
				"decision",
			);
		} finally {
			spy.mockRestore();
		}
	});
});

describe("what the decision log deliberately does not carry", () => {
	it("never logs the bearer token or the full claim set", async () => {
		const { events, logger } = captureEvents();
		const token = await signToken({
			sub: "user-1",
			scope: "read:project",
			// A claim an issuer might legitimately mint and that must not be
			// duplicated into a log stream with a different blast radius.
			email: "person@example.test",
		});

		await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read" });

		const [decision] = decisionsOf(events);
		const serialized = JSON.stringify(decision.obj);
		expect(serialized).not.toContain(token);
		expect(serialized).not.toContain("person@example.test");
		expect(decision.obj).not.toHaveProperty("payload");
		expect(decision.obj).not.toHaveProperty("token");
		expect(decision.obj).not.toHaveProperty("authorization");
	});

	it("never logs the caller-supplied context object", async () => {
		// `context` is free-form and forwarded verbatim to collectors, so it is
		// where a caller's own request payload ends up. Logging it would make the
		// audit stream a copy of whatever the enforcement layer happens to send.
		const { events, logger } = captureEvents();
		const token = await signToken({ sub: "user-1", scope: "read:project" });

		await request(createTestApp({ logger }))
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({
				resource: "project",
				action: "read",
				context: { cardNumber: "4111111111111111" },
			});

		const [decision] = decisionsOf(events);
		expect(JSON.stringify(decision.obj)).not.toContain("4111111111111111");
		expect(decision.obj).not.toHaveProperty("context");
	});

	it("logs no decision line for a request that was never decided", async () => {
		// 401 and 400 paths never reached the evaluator. A `decision` event for
		// them would make the allow/deny stream disagree with the metric.
		const { events, logger } = captureEvents();
		const app = createTestApp({ logger });

		const unauthenticated = await request(app)
			.post("/verify")
			.send({ resource: "project", action: "read" });
		const token = await signToken({ sub: "user-1", scope: "read:project" });
		const malformed = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "a..b", action: "read" });

		expect(unauthenticated.status).toBe(401);
		expect(malformed.status).toBe(400);
		expect(decisionsOf(events)).toHaveLength(0);
	});
});
