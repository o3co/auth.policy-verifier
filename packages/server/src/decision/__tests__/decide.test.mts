// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * One decision, without Express (#251).
 *
 * `createDecider` is what `POST /verify` runs once and `POST /verify/batch`
 * runs per entry: the two collects, the evaluation, the sorting of a failure
 * into a deny or a fault, the `decision` line and the counters. These tests
 * hold that contract through the function alone — no router, no request, no
 * response — so what the HTTP layer owns (wire validation, authentication,
 * status codes, the fault line) is deliberately not here. The router's own
 * suites still pin the wire.
 */
import { DotNotationResourceParser } from "@o3co/auth.policy-verifier.builtins";
import {
	type AnyRule,
	type AttributeCollector,
	AttributePipeline,
	type Attributes,
	type CollectorContext,
	type EventLogger,
	type RuleCollector,
	RulePipeline,
	readUntrustedRequestContext,
} from "@o3co/auth.policy-verifier.core";
import { describe, expect, it, vi } from "vitest";
import {
	createDecider,
	type DeciderConfig,
	DecisionFault,
	type DecisionInput,
	unwrapFault,
	type ValidatedDecisionRequest,
} from "#/decision/decide.mjs";
import type { DecisionMetrics } from "#/observability/decisionMetrics.mjs";

interface Captured {
	level: "info" | "warn" | "error";
	obj: Record<string, unknown>;
	msg: string;
}

function capture(): { events: Captured[]; logger: EventLogger } {
	const events: Captured[] = [];
	const push = (level: Captured["level"]) => (obj: Record<string, unknown>, msg?: string) => {
		events.push({ level, obj, msg: msg ?? "" });
	};
	return { events, logger: { info: push("info"), warn: push("warn"), error: push("error") } };
}

const named = (events: Captured[], msg: string) => events.filter((event) => event.msg === msg);

function countingMetrics() {
	return {
		observe: vi.fn(),
		observeCollectorFailure: vi.fn(),
	} satisfies DecisionMetrics;
}

const parser = new DotNotationResourceParser();

/** An entry the way the router hands one over: validated, its resource parsed. */
const entry = (
	resource = "project",
	action = "read",
	context?: Record<string, unknown>,
): ValidatedDecisionRequest => ({
	request: { resource, action, ...(context !== undefined ? { context } : {}) },
	resource: parser.parse(resource),
});

const input = (overrides: Partial<DecisionInput> = {}): DecisionInput => ({
	subject: { sub: "user-1" },
	signal: new AbortController().signal,
	...overrides,
});

const rule = (ruleType: string, passes: boolean, code = `${ruleType}_denied`): AnyRule => ({
	ruleType,
	code,
	message: `Denied by ${ruleType}`,
	verify: () => passes,
});

const rules = (...list: AnyRule[]): RuleCollector => ({
	async collect() {
		return list;
	},
});

const attributes = (
	write: (attrs: Attributes, context: CollectorContext) => void,
): AttributeCollector => ({
	async collect(context) {
		const attrs: Attributes = new Map();
		write(attrs, context);
		return attrs;
	},
});

/** A collector class, so a failure names it the way a configured one is named. */
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

interface Setup {
	attributeCollectors?: AttributeCollector[];
	ruleCollectors?: RuleCollector[];
	limits?: { collectorTimeoutMs?: number; deadlineMs?: number };
	config?: Partial<DeciderConfig>;
}

function decider(setup: Setup = {}) {
	const { events, logger } = capture();
	const metrics = countingMetrics();
	const decide = createDecider({
		attributePipeline: new AttributePipeline(setup.attributeCollectors ?? [], setup.limits),
		rulePipeline: new RulePipeline(setup.ruleCollectors ?? [rules(rule("scope", true))]),
		ruleTimeoutMs: 1_000,
		evaluateDeadlineMs: 2_000,
		includeEvaluation: false,
		logger,
		metrics,
		...setup.config,
	});
	return { decide, events, metrics };
}

const settled = (promise: Promise<unknown>): Promise<unknown> =>
	promise.then(
		() => undefined,
		(error: unknown) => error,
	);

describe("createDecider — one decision without Express (#251)", () => {
	it("answers allow, naming subject, resource, action and reason, and reports it exactly once", async () => {
		const { decide, events, metrics } = decider();
		const answer = await decide(entry(), input());
		expect(answer).toMatchObject({
			decision: "allow",
			subject: "user-1",
			resource: "project",
			action: "read",
		});
		expect(answer.reason.groups.map((group) => group.ruleType)).toEqual(["scope"]);
		expect("code" in answer).toBe(false);
		const lines = named(events, "decision");
		expect(lines).toHaveLength(1);
		expect(lines[0].level).toBe("info");
		expect(lines[0].obj).toMatchObject({
			sub: "user-1",
			resource: "project",
			action: "read",
			decision: "allow",
		});
		expect(typeof lines[0].obj.durationMs).toBe("number");
		expect(metrics.observe).toHaveBeenCalledTimes(1);
		expect(metrics.observe).toHaveBeenCalledWith(
			expect.objectContaining({ decision: "allow", code: undefined }),
		);
		expect(metrics.observeCollectorFailure).not.toHaveBeenCalled();
	});

	it("answers deny with the first failing group's code and message, and counts the code", async () => {
		const { decide, events, metrics } = decider({
			ruleCollectors: [rules(rule("scope", true), rule("role", false, "insufficient_role"))],
		});
		const answer = await decide(entry(), input());
		expect(answer).toMatchObject({
			decision: "deny",
			code: "insufficient_role",
			message: "Denied by role",
		});
		expect(named(events, "decision")).toHaveLength(1);
		expect(named(events, "decision")[0].obj).toMatchObject({
			decision: "deny",
			code: "insufficient_role",
		});
		expect(metrics.observe).toHaveBeenCalledTimes(1);
		expect(metrics.observe).toHaveBeenCalledWith(
			expect.objectContaining({ decision: "deny", code: "insufficient_role" }),
		);
	});

	it("a collector that runs out of time is a deny: one collector_timeout line, one count, one decision line", async () => {
		const { decide, events, metrics } = decider({
			attributeCollectors: [new StalledStoreCollector()],
			limits: { collectorTimeoutMs: 20, deadlineMs: 500 },
		});
		const answer = await decide(entry(), input({ requestId: "req-1" }));
		expect(answer).toEqual({
			subject: "user-1",
			resource: "project",
			action: "read",
			decision: "deny",
			code: "collector_timeout",
			message: "Authorization could not be decided in time",
			reason: { groups: [] },
		});
		const timeouts = named(events, "collector_timeout");
		expect(timeouts).toHaveLength(1);
		expect(timeouts[0].level).toBe("error");
		expect(timeouts[0].obj).toMatchObject({
			category: "collector_timeout",
			resource: "project",
			action: "read",
			requestId: "req-1",
		});
		expect(String(timeouts[0].obj.collector)).toContain("StalledStoreCollector");
		expect(metrics.observeCollectorFailure).toHaveBeenCalledTimes(1);
		expect(metrics.observeCollectorFailure).toHaveBeenCalledWith({
			collector: timeouts[0].obj.collector,
			category: "collector_timeout",
		});
		expect(named(events, "decision")).toHaveLength(1);
		expect(metrics.observe).toHaveBeenCalledTimes(1);
		expect(metrics.observe).toHaveBeenCalledWith(
			expect.objectContaining({ decision: "deny", code: "collector_timeout" }),
		);
	});

	it("collectors disagreeing on a scalar attribute deny attribute_conflict, and no collector is counted", async () => {
		const { decide, events, metrics } = decider({
			attributeCollectors: [
				attributes((attrs) => attrs.set("tenant", "acme")),
				attributes((attrs) => attrs.set("tenant", "globex")),
			],
		});
		const answer = await decide(entry(), input());
		expect(answer).toMatchObject({
			decision: "deny",
			code: "attribute_conflict",
			message: "Authorization inputs conflicted",
			reason: { groups: [] },
		});
		const conflicts = named(events, "attribute_conflict");
		expect(conflicts).toHaveLength(1);
		expect(conflicts[0].obj).toMatchObject({ category: "attribute_conflict" });
		expect(metrics.observeCollectorFailure).not.toHaveBeenCalled();
		expect(named(events, "decision")).toHaveLength(1);
		expect(metrics.observe).toHaveBeenCalledWith(
			expect.objectContaining({ decision: "deny", code: "attribute_conflict" }),
		);
	});

	it("an asynchronous rule that overruns ruleTimeoutMs denies rule_timeout, naming the rule", async () => {
		const stalled: AnyRule = {
			ruleType: "policy",
			code: "policy_denied",
			message: "Denied by policy",
			async: true,
			decide: () => new Promise<boolean>(() => {}),
		};
		const { decide, events, metrics } = decider({
			ruleCollectors: [rules(stalled)],
			config: { ruleTimeoutMs: 20, evaluateDeadlineMs: 500 },
		});
		const answer = await decide(entry(), input());
		expect(answer).toMatchObject({
			decision: "deny",
			code: "rule_timeout",
			message: "Authorization could not be decided in time",
			reason: { groups: [] },
		});
		const timeouts = named(events, "rule_timeout");
		expect(timeouts).toHaveLength(1);
		expect(timeouts[0].obj).toMatchObject({
			category: "rule_timeout",
			rule: { ruleType: "policy", code: "policy_denied" },
		});
		expect(metrics.observeCollectorFailure).not.toHaveBeenCalled();
		expect(named(events, "decision")).toHaveLength(1);
		expect(metrics.observe).toHaveBeenCalledWith(
			expect.objectContaining({ decision: "deny", code: "rule_timeout" }),
		);
	});

	it("a collector that throws is a fault, not an answer: DecisionFault names it, and nothing is reported", async () => {
		const { decide, events, metrics } = decider({
			attributeCollectors: [new EntitlementStoreCollector()],
		});
		const thrown = await settled(decide(entry(), input()));
		expect(thrown).toBeInstanceOf(DecisionFault);
		const fault = thrown as DecisionFault;
		expect(fault.original).toBeInstanceOf(Error);
		expect((fault.original as Error).message).toBe("entitlement store is down");
		expect(fault.failure).toMatchObject({ category: "collector_threw" });
		expect(String((fault.failure as { collector?: string }).collector)).toContain(
			"EntitlementStoreCollector",
		);
		// The fault line is the route's, once per request — see the router.
		expect(named(events, "decision")).toHaveLength(0);
		expect(events.filter((event) => event.level === "error")).toHaveLength(0);
		expect(metrics.observe).not.toHaveBeenCalled();
		expect(metrics.observeCollectorFailure).not.toHaveBeenCalled();
	});

	it("a rule that throws is a fault too, attributed to the rule", async () => {
		const throwing: AnyRule = {
			ruleType: "policy",
			code: "policy_denied",
			message: "Denied by policy",
			verify: () => {
				throw new Error("policy engine crashed");
			},
		};
		const { decide, events } = decider({ ruleCollectors: [rules(throwing)] });
		const thrown = await settled(decide(entry(), input()));
		expect(thrown).toBeInstanceOf(DecisionFault);
		expect((thrown as DecisionFault).failure).toEqual({
			category: "rule_threw",
			rule: { ruleType: "policy", code: "policy_denied" },
		});
		expect(named(events, "decision")).toHaveLength(0);
	});

	it("unwrapFault hands back the original with its classification, and sorts anything else as internal", () => {
		const original = new Error("entitlement store is down");
		const failure = { category: "collector_threw", collector: "attribute.collectors[0]" } as const;
		expect(unwrapFault(new DecisionFault(original, failure))).toEqual({ cause: original, failure });
		const other = new Error("the resource parser threw");
		expect(unwrapFault(other)).toEqual({ cause: other, failure: { category: "internal" } });
	});

	it("the credential reaches the collector context only when it is handed in (#175)", async () => {
		const seen: CollectorContext[] = [];
		const { decide } = decider({
			attributeCollectors: [
				attributes((_attrs, context) => {
					seen.push(context);
				}),
			],
		});
		await decide(entry(), input());
		expect("credential" in seen[0]).toBe(false);
		await decide(entry(), input({ credential: "token" }));
		expect(seen[1].credential).toBe("token");
	});

	it("what the transport chose to pass reaches the collectors as given: the headers, and the caller's context marked untrusted", async () => {
		const seen: CollectorContext[] = [];
		const { decide } = decider({
			attributeCollectors: [
				attributes((_attrs, context) => {
					seen.push(context);
				}),
			],
		});
		await decide(
			entry("project", "read", { tenant: { id: "acme" } }),
			input({ headers: { "x-request-id": "req-1" }, requestId: "req-1" }),
		);
		expect(seen[0].headers).toEqual({ "x-request-id": "req-1" });
		expect(readUntrustedRequestContext(seen[0].requestContext)).toEqual({ tenant: { id: "acme" } });
		expect(seen[0]).toMatchObject({
			subject: { sub: "user-1" },
			action: "read",
			resource: expect.objectContaining({ raw: "project" }),
		});
		await decide(entry(), input());
		expect(seen[1].headers).toBeUndefined();
		expect(seen[1].requestContext).toBeUndefined();
	});

	it("each decision gets its own copy of the shared headers: a collector's write does not reach the next decision (#251)", async () => {
		const seen: Array<Record<string, string> | undefined> = [];
		const { decide } = decider({
			attributeCollectors: [
				attributes((_attrs, context) => {
					seen.push(context.headers === undefined ? undefined : { ...context.headers });
					if (context.headers !== undefined) context.headers["x-poison"] = "yes";
				}),
			],
		});
		const shared = input({ headers: { "x-request-id": "req-1" }, requestId: "req-1" });
		await decide(entry("project:1"), shared);
		await decide(entry("project:2"), shared);
		expect(seen).toEqual([{ "x-request-id": "req-1" }, { "x-request-id": "req-1" }]);
		expect(shared.headers).toEqual({ "x-request-id": "req-1" });
	});

	it("the request id is on the decision line when there is one, and absent — not undefined — when there is none (#200)", async () => {
		const { decide, events } = decider();
		await decide(entry(), input({ requestId: "req-1" }));
		await decide(entry(), input());
		const lines = named(events, "decision");
		expect(lines).toHaveLength(2);
		expect(lines[0].obj.requestId).toBe("req-1");
		expect("requestId" in lines[1].obj).toBe(false);
	});

	it("a subject without a sub — or with an empty one — is named on neither the response nor the line (#158)", async () => {
		const { decide, events } = decider();
		const noSub = await decide(entry(), input({ subject: {} }));
		const emptySub = await decide(entry(), input({ subject: { sub: "" } }));
		expect("subject" in noSub).toBe(false);
		expect("subject" in emptySub).toBe(false);
		const lines = named(events, "decision");
		expect(lines).toHaveLength(2);
		for (const line of lines) expect("sub" in line.obj).toBe(false);
	});

	it("what a rule reported is on the line always, and on the response only when the composition includes it (#244)", async () => {
		const REVISION = `sha256:${"a".repeat(64)}`;
		const reporting: AnyRule = {
			ruleType: "cedar",
			code: "cedar_deny",
			message: "Denied by cedar",
			verify: (_attrs, report) => {
				report?.({ status: "completed", revision: REVISION });
				return true;
			},
		};
		const omitted = decider({ ruleCollectors: [rules(reporting)] });
		const answer = await omitted.decide(entry(), input());
		const group = answer.reason.groups[0];
		expect(group.evaluated[0]).not.toHaveProperty("evaluation");
		if (!group.passed) throw new Error("the reporting rule passes");
		expect(group.satisfiedBy).toBeDefined();
		expect(group.satisfiedBy).not.toHaveProperty("evaluation");
		expect(named(omitted.events, "decision")[0].obj.evaluations).toEqual([
			{
				ruleType: "cedar",
				code: "cedar_deny",
				passed: true,
				evaluation: { status: "completed", revision: REVISION },
			},
		]);

		const included = decider({
			ruleCollectors: [rules(reporting)],
			config: { includeEvaluation: true },
		});
		const carried = await included.decide(entry(), input());
		expect(carried.reason.groups[0].evaluated[0]).toMatchObject({
			evaluation: { status: "completed", revision: REVISION },
		});
	});

	it("the caller going away aborts the asynchronous rule in flight, and the decision fails with the caller's reason", async () => {
		let handed: AbortSignal | undefined;
		const pending: AnyRule = {
			ruleType: "policy",
			code: "policy_denied",
			message: "Denied by policy",
			async: true,
			decide: (_attrs, signal) => {
				handed = signal;
				return new Promise<boolean>(() => {});
			},
		};
		const { decide, events, metrics } = decider({
			ruleCollectors: [rules(pending)],
			config: { ruleTimeoutMs: 5_000, evaluateDeadlineMs: 5_000 },
		});
		const caller = new AbortController();
		const outcome = settled(decide(entry(), input({ signal: caller.signal })));
		await vi.waitFor(() => expect(handed).toBeDefined());
		const reason = new Error("the caller closed the connection");
		caller.abort(reason);
		const thrown = await outcome;
		expect(handed?.aborted).toBe(true);
		expect(thrown).toBeInstanceOf(DecisionFault);
		expect((thrown as DecisionFault).original).toBe(reason);
		expect(named(events, "decision")).toHaveLength(0);
		expect(metrics.observe).not.toHaveBeenCalled();
	});

	it("a library consumer's own evaluateOptions.signal is honoured beside the caller's", async () => {
		const consumer = new AbortController();
		const reason = new Error("the consumer's own deadline");
		consumer.abort(reason);
		const decided = vi.fn(async () => true);
		const asked: AnyRule = {
			ruleType: "policy",
			code: "policy_denied",
			message: "Denied by policy",
			async: true,
			decide: decided,
		};
		const { decide } = decider({
			ruleCollectors: [rules(asked)],
			config: { evaluateOptions: { signal: consumer.signal } },
		});
		const thrown = await settled(decide(entry(), input()));
		expect(thrown).toBeInstanceOf(DecisionFault);
		expect((thrown as DecisionFault).original).toBe(reason);
		expect(decided).not.toHaveBeenCalled();
	});

	/** An asynchronous rule that never answers and hands out the signal it was given. */
	function pendingRule(seen: (signal: AbortSignal) => void): AnyRule {
		return {
			ruleType: "policy",
			code: "policy_denied",
			message: "Denied by policy",
			async: true,
			decide: (_attrs, signal) => {
				seen(signal);
				return new Promise<boolean>(() => {});
			},
		};
	}

	it("a live consumer signal does not replace the caller's: the caller's abort still cancels the rule, with the caller's reason", async () => {
		// The already-aborted consumer above would pass if the code had written
		// `signal: config.evaluateOptions.signal` — replaced, not combined. This
		// is the other half: both signals live, the caller's is the one that fires.
		let handed: AbortSignal | undefined;
		const consumer = new AbortController();
		const { decide } = decider({
			ruleCollectors: [
				rules(
					pendingRule((signal) => {
						handed = signal;
					}),
				),
			],
			config: {
				evaluateOptions: { signal: consumer.signal },
				ruleTimeoutMs: 5_000,
				evaluateDeadlineMs: 5_000,
			},
		});
		const caller = new AbortController();
		const outcome = settled(decide(entry(), input({ signal: caller.signal })));
		await vi.waitFor(() => expect(handed).toBeDefined());
		const reason = new Error("the caller closed the connection");
		caller.abort(reason);
		const thrown = await outcome;
		expect(handed?.aborted).toBe(true);
		expect((thrown as DecisionFault).original).toBe(reason);
		expect(consumer.signal.aborted).toBe(false);
	});

	it("…and a live caller signal does not replace the consumer's: the consumer's abort cancels the rule, with the consumer's reason", async () => {
		let handed: AbortSignal | undefined;
		const consumer = new AbortController();
		const { decide } = decider({
			ruleCollectors: [
				rules(
					pendingRule((signal) => {
						handed = signal;
					}),
				),
			],
			config: {
				evaluateOptions: { signal: consumer.signal },
				ruleTimeoutMs: 5_000,
				evaluateDeadlineMs: 5_000,
			},
		});
		const caller = new AbortController();
		const outcome = settled(decide(entry(), input({ signal: caller.signal })));
		await vi.waitFor(() => expect(handed).toBeDefined());
		const reason = new Error("the consumer's own deadline");
		consumer.abort(reason);
		const thrown = await outcome;
		expect(handed?.aborted).toBe(true);
		expect((thrown as DecisionFault).original).toBe(reason);
		expect(caller.signal.aborted).toBe(false);
	});

	it("evaluateOptions other than the deadlines pass through: onEmptyRuleSet", async () => {
		const denies = decider({ ruleCollectors: [] });
		expect((await denies.decide(entry(), input())).decision).toBe("deny");
		const allows = decider({
			ruleCollectors: [],
			config: { evaluateOptions: { onEmptyRuleSet: "allow" } },
		});
		expect((await allows.decide(entry(), input())).decision).toBe("allow");
	});
});
