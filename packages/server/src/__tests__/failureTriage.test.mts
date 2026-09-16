// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Failure triage for the verify router (#200, item 8 of #126).
 *
 * #107 gave every failure path a structured event and #111 gave decisions their
 * counters, but a decision that could not be made still arrived as
 * `verify_internal_error { err, endpoint }`: no word on WHICH collector failed,
 * no category an operator could filter on without a regex over `err.message`,
 * and nothing on a dashboard that pointed at one misbehaving fact source.
 *
 * So every failure line the router emits for a decision it could not make —
 * `verify_internal_error` and the three deny events `collector_timeout`,
 * `rule_timeout`, `attribute_conflict` — now carries a `category` from one
 * closed set, and names the collector or rule when there is one to name; and
 * `auth_collector_failures_total{collector,category}` counts the collector
 * failures among them.
 *
 * What must stay true is tested as hard as what is new: the wire answers are
 * unchanged, the labels are bounded by configuration, and neither the
 * credential, the claims nor the caller's context reaches a line or a label.
 */
import {
	DotNotationResourceParser,
	PayloadScopeCollector,
	ResourceActionScopeRuleCollector,
} from "@o3co/auth.policy-verifier.builtins";
import {
	type AsyncRule,
	type AttributeCollector,
	AttributeConflictError,
	AttributePipeline,
	type Attributes,
	CollectorTimeoutError,
	type EventLogger,
	FailureRecord,
	type FailureSource,
	type Rule,
	type RuleCollector,
	RulePipeline,
	RuleTimeoutError,
	readUntrustedRequestContext,
} from "@o3co/auth.policy-verifier.core";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { HS256KeyResolverFactory } from "#/jwt/index.mjs";
import { classifyFailure, FAILURE_CATEGORIES } from "#/observability/failure.mjs";
import { createMetrics, MAX_COLLECTOR_LABELS } from "#/observability/metrics.mjs";
import { createVerifyRouter, type VerifyRouterConfig } from "#/routes/verify.mjs";

/** 64 hex characters — 32 decoded bytes, the entropy floor #114 enforces. */
const JWT_SECRET = "11".repeat(32);
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
	const push = (level: CapturedEvent["level"]) => (obj: Record<string, unknown>, msg?: string) => {
		events.push({ level, obj, msg: msg ?? "" });
	};
	return { events, logger: { info: push("info"), warn: push("warn"), error: push("error") } };
}

const named = (events: CapturedEvent[], msg: string) => events.filter((e) => e.msg === msg);

async function signToken(payload: Record<string, unknown>): Promise<string> {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuedAt()
		.setExpirationTime("1h")
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.sign(hs256Key.key as import("node:crypto").KeyObject);
}

/** A collector class, so the failure names it the way a configured one would be named. */
class EntitlementStoreCollector implements AttributeCollector {
	async collect(): Promise<Attributes> {
		throw new Error("entitlement store is down");
	}
}

class StalledStoreCollector implements AttributeCollector {
	collect(): Promise<Attributes> {
		return new Promise<Attributes>(() => {});
	}
}

const scopeRuleCollectors = (): RuleCollector[] => [new ResourceActionScopeRuleCollector()];

interface AppOptions {
	attributeCollectors?: AttributeCollector[];
	ruleCollectors?: RuleCollector[];
	router?: Partial<VerifyRouterConfig>;
	/** Mounted in front of the verify router. */
	before?: express.RequestHandler;
}

/** The verify router and `/metrics` on one app, so a test can read what it counted. */
function createTestApp(options: AppOptions = {}) {
	const { events, logger } = captureEvents();
	const metrics = createMetrics();
	const app = express();
	app.use(metrics.router);
	if (options.before) app.use(options.before);
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
			logger,
			metrics: metrics.decisions,
			resourceParser: new DotNotationResourceParser(),
			attributePipeline: new AttributePipeline(
				options.attributeCollectors ?? [new PayloadScopeCollector()],
				{ collectorTimeoutMs: 30, deadlineMs: 1_000 },
			),
			rulePipeline: new RulePipeline(options.ruleCollectors ?? scopeRuleCollectors()),
			...options.router,
		}),
	);
	return { app, events };
}

const decide = async (
	app: express.Express,
	body: Record<string, unknown> = { resource: "project", action: "read" },
	endpoint: "/verify" | "/verify/batch" = "/verify",
) =>
	request(app)
		.post(endpoint)
		.set("Authorization", `Bearer ${await signToken({ sub: "user-1", scope: "read:project" })}`)
		.send(endpoint === "/verify" ? body : { decisions: [body] });

const scrape = async (app: express.Express) => (await request(app).get("/metrics")).text;

/** A line rendered the way a JSON logger renders it: errors with every own property, message and stack. */
const render = (event: CapturedEvent): string =>
	JSON.stringify(event.obj, (_key, value) =>
		value instanceof Error
			? { ...value, name: value.name, message: value.message, stack: value.stack }
			: value,
	);

describe("the failure category set (#200)", () => {
	it("is closed, and every value is one an operator can filter on exactly", () => {
		expect([...FAILURE_CATEGORIES]).toEqual([
			"collector_timeout",
			"collector_threw",
			"attribute_conflict",
			"rule_timeout",
			"rule_threw",
			"body_rejected",
			"internal",
		]);
	});

	/** A record holding one source for `cause`, as the runner or evaluator would have left it. */
	const recorded = (cause: unknown, source: FailureSource): FailureRecord => {
		const failures = new FailureRecord();
		failures.record(cause, source);
		return failures;
	};
	const timeout = (collector: string) =>
		new CollectorTimeoutError({
			pipeline: "attribute",
			limit: "collector",
			timeoutMs: 20,
			collector,
		});
	const deadline = new CollectorTimeoutError({
		pipeline: "rule",
		limit: "deadline",
		timeoutMs: 50,
	});
	const ruleTimeout = (ruleType: string, code: string) =>
		new RuleTimeoutError({ ruleType, code, timeoutMs: 20 });
	const forgedName = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig";
	const attributed = timeout("attribute.collectors[2] (StalledStoreCollector)");
	const forged = timeout(forgedName);
	const ruleTimedOut = ruleTimeout("cedar", "cedar_deny");
	const unattributedRule = ruleTimeout("cedar", "cedar_deny");
	const outage = new Error("store is down");
	const ruleFault = new Error("rule bug");
	const shapedRuleFault = new Error("rule bug");

	it.each<[string, unknown, FailureRecord | undefined, unknown]>([
		[
			"a collector's own timeout, naming the collector the runner recorded",
			attributed,
			recorded(attributed, {
				kind: "collector",
				pipeline: "attribute",
				collector: "attribute.collectors[2] (StalledStoreCollector)",
			}),
			{
				category: "collector_timeout",
				collector: "attribute.collectors[2] (StalledStoreCollector)",
			},
		],
		[
			"a fan-out deadline, naming the list rather than any one entry of it",
			deadline,
			recorded(deadline, { kind: "deadline", pipeline: "rule" }),
			{ category: "collector_timeout", collector: "rule.collectors" },
		],
		[
			"a timeout nothing recorded, naming no collector — not the one the error claims",
			forged,
			new FailureRecord(),
			{ category: "collector_timeout", collector: "unattributed" },
		],
		[
			"a rule timeout, naming the rule the evaluator recorded",
			ruleTimedOut,
			recorded(ruleTimedOut, { kind: "rule", ruleType: "cedar", code: "cedar_deny" }),
			{ category: "rule_timeout", rule: { ruleType: "cedar", code: "cedar_deny" } },
		],
		[
			"a rule timeout nothing recorded",
			unattributedRule,
			undefined,
			{ category: "rule_timeout", rule: { ruleType: "unattributed", code: "unattributed" } },
		],
		[
			"a collector that threw",
			outage,
			recorded(outage, { kind: "collector", pipeline: "rule", collector: "rule.collectors[0]" }),
			{ category: "collector_threw", collector: "rule.collectors[0]" },
		],
		[
			"a rule that threw",
			ruleFault,
			recorded(ruleFault, { kind: "rule", ruleType: "tenant", code: "wrong_tenant" }),
			{ category: "rule_threw", rule: { ruleType: "tenant", code: "wrong_tenant" } },
		],
		[
			"a rule whose metadata is not identifier-shaped, redacting what is not",
			shapedRuleFault,
			recorded(shapedRuleFault, {
				kind: "rule",
				ruleType: "tenant",
				code: "deny for victim@example.com",
			}),
			{ category: "rule_threw", rule: { ruleType: "tenant", code: "redacted" } },
		],
		[
			"an attribute conflict",
			new AttributeConflictError("tenantId"),
			undefined,
			{ category: "attribute_conflict" },
		],
		[
			"anything nothing attributed",
			new Error("boom"),
			new FailureRecord(),
			{ category: "internal" },
		],
		["a rejection that is not an object", "boom", undefined, { category: "internal" }],
	])("classifies %s", (_what, cause, failures, expected) => {
		expect(classifyFailure(cause, failures)).toEqual(expected);
	});

	it.each([
		["a credential", "Bearer eyJhbGciOiJIUzI1NiJ9"],
		["an email", "victim@example.com"],
		["an identifier that starts with a digit — an SSN", "078-05-1120"],
		["whitespace", "wrong tenant"],
		["a line break", "wrong_tenant\ninjected"],
		["a scope-shaped value", "read:project"],
		["more than 64 characters", `c${"x".repeat(64)}`],
		["nothing", ""],
	])("redacts rule metadata carrying %s", (_what, value) => {
		const fault = new Error("rule bug");
		const failures = recorded(fault, { kind: "rule", ruleType: value, code: value });

		expect(classifyFailure(fault, failures)).toEqual({
			category: "rule_threw",
			rule: { ruleType: "redacted", code: "redacted" },
		});
	});
});

describe("verify_internal_error names what failed (#200)", () => {
	it("names the attribute collector that threw, on POST /verify", async () => {
		const { app, events } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), new EntitlementStoreCollector()],
		});

		const res = await decide(app);

		// The wire answer is exactly what it was: the category is for the operator.
		expect(res.status).toBe(500);
		expect(res.body).toEqual({
			decision: "deny",
			code: "internal_error",
			message: "Internal server error",
		});
		const [event] = named(events, "verify_internal_error");
		expect(event).toMatchObject({
			level: "error",
			obj: {
				endpoint: "/verify",
				category: "collector_threw",
				collector: "attribute.collectors[1] (EntitlementStoreCollector)",
			},
		});
		expect((event.obj.err as Error).message).toBe("entitlement store is down");
	});

	it("names the rule collector that threw, on POST /verify/batch", async () => {
		const failing: RuleCollector = {
			collect: () => Promise.reject(new Error("rule store is down")),
		};
		const { app, events } = createTestApp({
			ruleCollectors: [new ResourceActionScopeRuleCollector(), failing],
		});

		const res = await decide(app, undefined, "/verify/batch");

		expect(res.status).toBe(500);
		expect(named(events, "verify_internal_error")[0].obj).toMatchObject({
			endpoint: "/verify/batch",
			category: "collector_threw",
			collector: "rule.collectors[1]",
		});
	});

	it("names the rule whose verify threw", async () => {
		const broken: Rule = {
			ruleType: "tenant",
			code: "wrong_tenant",
			message: "Wrong tenant",
			verify: () => {
				throw new TypeError("cannot read properties of undefined");
			},
		};
		const { app, events } = createTestApp({ ruleCollectors: [{ collect: async () => [broken] }] });

		const res = await decide(app);

		expect(res.status).toBe(500);
		const [event] = named(events, "verify_internal_error");
		expect(event.obj).toMatchObject({
			category: "rule_threw",
			rule: { ruleType: "tenant", code: "wrong_tenant" },
		});
		expect(event.obj).not.toHaveProperty("collector");
	});

	it("files a CollectorTimeoutError an authenticator threw under internal, naming no collector", async () => {
		// The class is public. Thrown from anywhere but a decision's own collect,
		// it is not a collector timeout, and what it claims to name is not read.
		const forgedName = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig";
		const { app, events } = createTestApp({
			router: {
				jwt: undefined,
				authenticator: {
					authenticate: async () => {
						throw new CollectorTimeoutError({
							pipeline: "attribute",
							limit: "collector",
							timeoutMs: 1,
							collector: forgedName,
						});
					},
				},
			},
		});

		const res = await decide(app);

		expect(res.status).toBe(500);
		const [event] = named(events, "verify_internal_error");
		expect(event.obj).toMatchObject({ category: "internal" });
		expect(event.obj).not.toHaveProperty("collector");
		expect(await scrape(app)).not.toContain(forgedName);
	});

	it("names the collector's position, not the name inside a CollectorTimeoutError it built", async () => {
		const forgedName = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig";
		const forging: AttributeCollector = {
			collect: () =>
				Promise.reject(
					new CollectorTimeoutError({
						pipeline: "attribute",
						limit: "collector",
						timeoutMs: 1,
						collector: forgedName,
					}),
				),
		};
		const { app, events } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), forging],
		});

		const res = await decide(app);

		// Still the deny its class earns; only the name is the runner's.
		expect(res.status).toBe(403);
		expect(named(events, "collector_timeout")[0].obj).toMatchObject({
			category: "collector_timeout",
			collector: "attribute.collectors[1]",
		});
		const metrics = await scrape(app);
		expect(metrics).toContain(
			'auth_collector_failures_total{collector="attribute.collectors[1]",category="collector_timeout"} 1',
		);
		expect(metrics).not.toContain("eyJhbGciOiJIUzI1NiJ9");
	});

	it("refuses evaluateOptions.failures — one record shared across decisions is the defect it prevents", () => {
		expect(() =>
			createTestApp({
				router: { evaluateOptions: { failures: new FailureRecord() } as never },
			}),
		).toThrow(
			"createVerifyRouter: evaluateOptions.failures is not read — the router keeps one failure record per decision",
		);
	});

	it("files a fault nothing attributed under internal, naming nothing", async () => {
		// A resource parser that throws something other than ResourceParseError is
		// a fault in the parser, not in any collector.
		const { app, events } = createTestApp({
			router: {
				resourceParser: {
					parse: () => {
						throw new Error("parser bug");
					},
				},
			},
		});

		const res = await decide(app);

		expect(res.status).toBe(500);
		const [event] = named(events, "verify_internal_error");
		expect(event.obj).toMatchObject({ endpoint: "/verify", category: "internal" });
		expect(event.obj).not.toHaveProperty("collector");
		expect(event.obj).not.toHaveProperty("rule");
	});

	it("files a body-parser failure the envelope does not map under body_rejected", async () => {
		// A middleware in front of the router that set the stream's encoding: the
		// parser refuses to read it (`stream.encoding.set`), and that reaches the
		// router's terminal handler rather than either route.
		const { app, events } = createTestApp({
			before: (req, _res, next) => {
				req.setEncoding("utf8");
				next();
			},
		});

		const res = await decide(app);

		expect(res.status).toBe(500);
		expect(res.body.code).toBe("internal_error");
		expect(named(events, "verify_internal_error")[0].obj).toMatchObject({
			endpoint: "/verify",
			category: "body_rejected",
		});
	});
});

describe("the deny events carry the category too (#200)", () => {
	it("names the collector that overran its budget on the collector_timeout line", async () => {
		const { app, events } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), new StalledStoreCollector()],
		});

		const res = await decide(app);

		expect(res.status).toBe(403);
		expect(res.body.code).toBe("collector_timeout");
		expect(named(events, "collector_timeout")[0].obj).toMatchObject({
			category: "collector_timeout",
			collector: "attribute.collectors[1] (StalledStoreCollector)",
		});
	});

	it("names the rule that did not answer on the rule_timeout line", async () => {
		const never: AsyncRule = {
			ruleType: "cedar",
			code: "cedar_deny",
			message: "Denied by Cedar policy",
			async: true,
			decide: () => new Promise<boolean>(() => {}),
		};
		const { app, events } = createTestApp({
			ruleCollectors: [{ collect: async () => [never] }],
			router: { ruleTimeoutMs: 20 },
		});

		const res = await decide(app);

		expect(res.status).toBe(403);
		expect(named(events, "rule_timeout")[0].obj).toMatchObject({
			category: "rule_timeout",
			rule: { ruleType: "cedar", code: "cedar_deny" },
		});
	});

	it("files an attribute conflict under its own category", async () => {
		const writes = (value: string): AttributeCollector => ({
			collect: async () => new Map([["tenantId", value]]),
		});
		const { app, events } = createTestApp({ attributeCollectors: [writes("a"), writes("b")] });

		const res = await decide(app);

		expect(res.status).toBe(403);
		expect(named(events, "attribute_conflict")[0].obj).toMatchObject({
			category: "attribute_conflict",
		});
	});
});

describe("auth_collector_failures_total{collector,category} (#200)", () => {
	it("is published before any collector has failed", async () => {
		const { app } = createTestApp();

		expect(await scrape(app)).toContain("# TYPE auth_collector_failures_total counter");
	});

	it("counts a collector that threw, by its configured name", async () => {
		const { app } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), new EntitlementStoreCollector()],
		});

		await decide(app);
		await decide(app);

		expect(await scrape(app)).toContain(
			'auth_collector_failures_total{collector="attribute.collectors[1] (EntitlementStoreCollector)",category="collector_threw"} 2',
		);
	});

	it("counts a collector timeout, and a deadline under the list it belongs to", async () => {
		const slow: AttributeCollector = {
			collect: async () => {
				await new Promise((resolve) => setTimeout(resolve, 20));
				return new Map();
			},
		};
		const { app } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), new StalledStoreCollector()],
		});
		const deadline = createTestApp({
			router: {
				attributePipeline: new AttributePipeline([slow, slow, slow], {
					collectorTimeoutMs: 1_000,
					deadlineMs: 30,
					concurrency: 1,
				}),
			},
		});

		await decide(app);
		await decide(deadline.app);

		expect(await scrape(app)).toContain(
			'auth_collector_failures_total{collector="attribute.collectors[1] (StalledStoreCollector)",category="collector_timeout"} 1',
		);
		expect(await scrape(deadline.app)).toContain(
			'auth_collector_failures_total{collector="attribute.collectors",category="collector_timeout"} 1',
		);
	});

	it("counts nothing that is not a collector's failure", async () => {
		const broken: Rule = {
			ruleType: "tenant",
			code: "wrong_tenant",
			message: "Wrong tenant",
			verify: () => {
				throw new Error("rule bug");
			},
		};
		const { app } = createTestApp({ ruleCollectors: [{ collect: async () => [broken] }] });

		await decide(app);

		expect(await scrape(app)).not.toMatch(/^auth_collector_failures_total\{/m);
	});

	it("collapses collector names past the cap into `other`", async () => {
		// Collector names are fixed by configuration, but `CollectorTimeoutError`
		// is a public class a collector can construct with any name it likes —
		// the same reason deny codes are capped.
		const metrics = createMetrics();
		const app = express().use(metrics.router);
		for (let i = 0; i < MAX_COLLECTOR_LABELS + 3; i += 1) {
			metrics.decisions.observeCollectorFailure?.({
				collector: `attribute.collectors[${i}]`,
				category: "collector_threw",
			});
		}

		const text = await scrape(app);
		expect(text).toContain(
			'auth_collector_failures_total{collector="attribute.collectors[0]",category="collector_threw"} 1',
		);
		expect(text).toContain(
			'auth_collector_failures_total{collector="other",category="collector_threw"} 3',
		);
	});
});

describe("attribution is per decision, not per error object (#200 review)", () => {
	/**
	 * One rejection shared by every collector that awaits it — the shape a
	 * memoised downstream call or a circuit breaker's cached failure takes.
	 * `fail()` rejects it once every expected caller is already waiting on it,
	 * so all of their rejections land in the same turn, before any route has
	 * caught its own.
	 */
	function sharedFailure(waiters: number) {
		const error = new Error("shared downstream call failed");
		let reject!: (reason: unknown) => void;
		const promise = new Promise<never>((_, r) => {
			reject = r;
		});
		promise.catch(() => {});
		let waiting = 0;
		let allWaiting!: () => void;
		const ready = new Promise<void>((resolve) => {
			allWaiting = resolve;
		});
		const wait = async (): Promise<never> => {
			waiting += 1;
			if (waiting === waiters) allWaiting();
			return promise;
		};
		return { error, wait, fail: async () => ready.then(() => reject(error)) };
	}

	it("names each request's own collector when concurrent requests fail with the same object", async () => {
		const shared = sharedFailure(2);
		class SharedClientCollector implements AttributeCollector {
			async collect(context: Parameters<AttributeCollector["collect"]>[0]): Promise<Attributes> {
				return context.action === "read" ? shared.wait() : new Map();
			}
		}
		const sharedRules: RuleCollector = {
			collect: async (context) => (context.action === "write" ? shared.wait() : []),
		};
		const { app, events } = createTestApp({
			attributeCollectors: [new PayloadScopeCollector(), new SharedClientCollector()],
			ruleCollectors: [new ResourceActionScopeRuleCollector(), sharedRules],
		});
		const token = await signToken({ sub: "user-1", scope: "read:project write:project" });
		const send = (action: string) =>
			request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.set("x-request-id", action)
				.send({ resource: "project", action });

		const [read, write] = await Promise.all([send("read"), send("write"), shared.fail()]);

		expect([read.status, write.status]).toEqual([500, 500]);
		const byRequest = Object.fromEntries(
			named(events, "verify_internal_error").map((e) => [e.obj.requestId, e.obj.collector]),
		);
		expect(byRequest).toEqual({
			read: "attribute.collectors[1] (SharedClientCollector)",
			write: "rule.collectors[1]",
		});
		const metrics = await scrape(app);
		expect(metrics).toContain(
			'auth_collector_failures_total{collector="attribute.collectors[1] (SharedClientCollector)",category="collector_threw"} 1',
		);
		expect(metrics).toContain(
			'auth_collector_failures_total{collector="rule.collectors[1]",category="collector_threw"} 1',
		);
	});

	it("names the collector that recorded first when both pipelines of one decision fail with the same object", async () => {
		// Both failed the decision; the line names one and the counter counts
		// one. The first to record is the attribute collector — its pipeline
		// starts first, so it was waiting first and its rejection lands first.
		const shared = sharedFailure(2);
		class SharedClientCollector implements AttributeCollector {
			async collect(): Promise<Attributes> {
				return shared.wait();
			}
		}
		const sharedRules: RuleCollector = { collect: async () => shared.wait() };
		const { app, events } = createTestApp({
			attributeCollectors: [new SharedClientCollector()],
			ruleCollectors: [sharedRules],
		});

		const [res] = await Promise.all([decide(app), shared.fail()]);

		expect(res.status).toBe(500);
		const failures = named(events, "verify_internal_error");
		expect(failures).toHaveLength(1);
		expect(failures[0].obj).toMatchObject({
			category: "collector_threw",
			collector: "attribute.collectors[0] (SharedClientCollector)",
		});
		expect(failures[0].obj.err).toBe(shared.error);
		const counted = (await scrape(app))
			.split("\n")
			.filter((line) => line.startsWith("auth_collector_failures_total{"));
		expect(counted).toEqual([
			'auth_collector_failures_total{collector="attribute.collectors[0] (SharedClientCollector)",category="collector_threw"} 1',
		]);
	});
});

describe("redaction: nothing request-derived reaches a failure line or a label (#200)", () => {
	it("keeps request-derived rule metadata out of the failure fields (#200 review)", async () => {
		// A rule collector may build its rules per request, and nothing stops
		// one deriving `ruleType` or `code` from the claims or the context.
		const perRequest: RuleCollector = {
			collect: async (context) => {
				const ssn = String(readUntrustedRequestContext(context.requestContext)?.ssn);
				const email = String(context.subject.email);
				const throwing: Rule = {
					ruleType: email,
					code: ssn,
					message: "Denied",
					verify: () => {
						throw new Error("rule bug");
					},
				};
				const stalling: AsyncRule = {
					ruleType: email,
					code: ssn,
					message: "Denied",
					async: true,
					decide: () => new Promise<boolean>(() => {}),
				};
				return context.action === "read" ? [throwing] : [stalling];
			},
		};
		const { app, events } = createTestApp({
			ruleCollectors: [perRequest],
			router: { ruleTimeoutMs: 20 },
		});
		const token = await signToken({
			sub: "user-1",
			scope: "read:project write:project",
			email: "victim@example.com",
		});
		const send = (action: string) =>
			request(app)
				.post("/verify")
				.set("Authorization", `Bearer ${token}`)
				.send({ resource: "project", action, context: { ssn: "078-05-1120" } });

		expect((await send("read")).status).toBe(500);
		expect((await send("write")).status).toBe(403);

		const [threw] = named(events, "verify_internal_error");
		const [timedOut] = named(events, "rule_timeout");
		for (const event of [threw, timedOut]) {
			expect(event.obj.rule).toEqual({ ruleType: "redacted", code: "redacted" });
		}
		// The whole line, error included, for the fault: its error names neither.
		for (const secret of [token, "victim@example.com", "078-05-1120"]) {
			expect(render(threw)).not.toContain(secret);
		}
	});

	it("keeps the credential, the claims and the caller's context out of the lines and /metrics", async () => {
		// The collector is handed all three — `credentialToCollectors: "expose"`
		// puts the raw token on its context — and fails anyway. None of what it
		// was handed may come back out through the triage fields.
		let seen: string | undefined;
		class TokenForwardingCollector implements AttributeCollector {
			async collect(context: Parameters<AttributeCollector["collect"]>[0]): Promise<Attributes> {
				seen = context.credential;
				throw new Error("downstream refused the forwarded token");
			}
		}
		const { app, events } = createTestApp({
			attributeCollectors: [new TokenForwardingCollector()],
			router: { credentialToCollectors: "expose" },
		});
		const token = await signToken({
			sub: "user-1",
			scope: "read:project",
			email: "victim@example.com",
		});

		const res = await request(app)
			.post("/verify")
			.set("Authorization", `Bearer ${token}`)
			.send({ resource: "project", action: "read", context: { ssn: "078-05-1120" } });

		expect(res.status).toBe(500);
		expect(seen).toBe(token);
		const failures = events.filter((e) => e.level === "error");
		expect(failures.map((e) => e.msg)).toEqual(["verify_internal_error"]);
		const metrics = await scrape(app);
		for (const secret of [token, "victim@example.com", "078-05-1120", "user-1"]) {
			for (const failure of failures) expect(render(failure)).not.toContain(secret);
			expect(metrics).not.toContain(secret);
		}
	});
});
