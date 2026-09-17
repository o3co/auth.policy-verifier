// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * The collector against the port, not against Cedar: a scripted engine
 * answers whatever a case needs, so every row of the answer table and both
 * kinds of rule are pinned here without an evaluator in the dependency graph.
 * Cedar's own semantics through the real evaluator live in
 * `packages/cedar-wasm`.
 */

import type {
	AsyncRule,
	Attributes,
	CollectorContext,
	Logger,
	Rule,
	RuleEvaluation,
} from "@o3co/auth.policy-verifier.core";
import { evaluate, isAsyncRule } from "@o3co/auth.policy-verifier.core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	CedarPolicyRuleCollector,
	type NoDeterminingPolicy,
} from "../CedarPolicyRuleCollector.mjs";
import { type CedarDecision, CedarEngineError, registerCedarEngine } from "../engine.mjs";
import { computePolicyRevision } from "../policySource.mjs";
import { ALLOW, FORBIDDEN, scriptedEngine, UNDETERMINED } from "./scriptedEngine.mjs";

// "wasm" so that the engine-less default resolves here, as it does in a
// deployment that imported the wasm package; the asynchronous one under a
// name no real engine takes, selected explicitly.
//
// #244: the synchronous one vouches for the revision it evaluated, as the real
// wasm engine does; the asynchronous one does not, as the http engine cannot.
// `fake-async-vouching` is the remote engine that does not exist yet — one
// whose answers name a revision — so the confirmation contract is pinned for
// the day one does.
const sync = scriptedEngine("wasm", false, { confirmsRevision: true });
const async = scriptedEngine("fake-async", true);
const asyncVouching = scriptedEngine("fake-async-vouching", true, { confirmsRevision: true });
registerCedarEngine(sync);
registerCedarEngine(async);
registerCedarEngine(asyncVouching);

/** A context the collector must never read — everything reaches the rule via attrs. */
const context: CollectorContext = {
	subject: { sub: "user-1" },
	resource: { raw: "document:42", resourceType: "document", resourceId: "42" },
	action: "read",
	signal: new AbortController().signal,
};

const REQUEST_FACTS: ReadonlyArray<[string, unknown]> = [
	["userId", "alice"],
	["requestAction", "read"],
	["requestResourceType", "Document"],
	["requestResourceId", "42"],
];

function attrsWith(entries: ReadonlyArray<[string, unknown]> = []): Attributes {
	return new Map<string, unknown>([...REQUEST_FACTS, ...entries]);
}

function fakeLogger(): { logger: Logger; error: ReturnType<typeof vi.fn> } {
	const error = vi.fn();
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error,
		fatal: vi.fn(),
		child: (): Logger => logger,
	} as Logger;
	return { logger, error };
}

const PERMIT_ALL = "permit(principal, action, resource);";

async function collectSync(config: Record<string, unknown>, logger?: Logger): Promise<Rule> {
	const collector = await CedarPolicyRuleCollector.create(config, logger ? { logger } : undefined);
	const rules = await collector.collect(context);
	expect(rules).toHaveLength(1);
	expect(isAsyncRule(rules[0])).toBe(false);
	return rules[0] as Rule;
}

async function collectAsync(config: Record<string, unknown>, logger?: Logger): Promise<AsyncRule> {
	const collector = await CedarPolicyRuleCollector.create(
		{ ...config, engine: "fake-async" },
		logger ? { logger } : undefined,
	);
	const rules = await collector.collect(context);
	expect(rules).toHaveLength(1);
	expect(isAsyncRule(rules[0])).toBe(true);
	return rules[0] as AsyncRule;
}

const NEVER_ABORTS = new AbortController().signal;

beforeEach(() => {
	for (const engine of [sync, async, asyncVouching]) {
		engine.answer = () => ALLOW;
		engine.requests.length = 0;
	}
});

describe("CedarPolicyRuleCollector — config validation", () => {
	it("requires one of policyDir / policies", async () => {
		await expect(CedarPolicyRuleCollector.create({})).rejects.toThrow(
			/one of policyDir or policies/,
		);
	});

	it("refuses both policyDir and policies", async () => {
		await expect(
			CedarPolicyRuleCollector.create({ policyDir: "x", policies: PERMIT_ALL }),
		).rejects.toThrow(/mutually exclusive/);
	});

	it("refuses a policy set the engine cannot parse, at construction, in the engine's words", async () => {
		await expect(CedarPolicyRuleCollector.create({ policies: "permit(when;" })).rejects.toThrow(
			/CedarPolicyRuleCollector: policies \(inline\) failed to parse/,
		);
	});

	it("refuses an unknown onNoDeterminingPolicy", async () => {
		await expect(
			CedarPolicyRuleCollector.create({
				policies: PERMIT_ALL,
				onNoDeterminingPolicy: "allow" as unknown as NoDeterminingPolicy,
			}),
		).rejects.toThrow(/onNoDeterminingPolicy must be one of abstain, deny/);
	});

	it("refuses abstain over an asynchronous policy set, at boot (v0.10.0 audit)", async () => {
		// An out-of-process engine that restarted empty answers every request
		// "deny, no determining policy" — byte-identical to a request the set
		// covers and nothing matched. Under abstain every `forbid` then stops
		// applying: a routine container recreate turns deny into allow. The port
		// cannot tell the two apart, so the combination is refused.
		await expect(
			CedarPolicyRuleCollector.create({
				policies: PERMIT_ALL,
				engine: "fake-async",
				onNoDeterminingPolicy: "abstain",
			}),
		).rejects.toThrow(
			/onNoDeterminingPolicy = "abstain" cannot be used with the asynchronous "fake-async" engine/,
		);
		// The way out is named concretely. An upgrade from 0.9.0 that kept abstain
		// and never imported cedar-wasm lands here with the http engine picked by
		// default: "use deny" is the wrong fix for a missing import.
		await expect(
			CedarPolicyRuleCollector.create({
				policies: PERMIT_ALL,
				engine: "fake-async",
				onNoDeterminingPolicy: "abstain",
			}),
		).rejects.toThrow(/import "@o3co\/auth\.policy-verifier\.cedar-wasm" and set engine = "wasm"/);
		// Refused before the engine is asked to load anything (review): a remote
		// load has side effects — the policy set is pushed, the agent reserved.
		expect(async.loads).toHaveLength(0);
		// The same set in-process is fine: the evaluator cannot lose it.
		await expect(
			CedarPolicyRuleCollector.create({ policies: PERMIT_ALL, onNoDeterminingPolicy: "abstain" }),
		).resolves.toBeDefined();
	});

	it("warns when no engine is named — which evaluator decides belongs in config (v0.10.0 audit)", async () => {
		// With `engine` absent the choice is made by what happens to be imported:
		// a transitive dependency pulling in cedar-wasm silently flips a
		// deployment from out-of-process to in-process.
		const warn = vi.fn();
		const info = vi.fn();
		const logger = { ...fakeLogger().logger, warn, info } as Logger;
		await CedarPolicyRuleCollector.create({ policies: PERMIT_ALL }, { logger });
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({ engine: "wasm" }),
			expect.stringMatching(/cedar engine selected by default — set engine/),
		);
		warn.mockClear();
		await CedarPolicyRuleCollector.create({ policies: PERMIT_ALL, engine: "wasm" }, { logger });
		expect(warn).not.toHaveBeenCalled();
		expect(info).toHaveBeenCalledWith(expect.anything(), "cedar engine selected by config");
	});

	it("refuses a non-boolean logEvaluationErrors", async () => {
		await expect(
			CedarPolicyRuleCollector.create({
				policies: PERMIT_ALL,
				logEvaluationErrors: "yes" as unknown as boolean,
			}),
		).rejects.toThrow(/logEvaluationErrors must be a boolean/);
	});

	it("refuses a malformed entity attribute mapping", async () => {
		await expect(
			CedarPolicyRuleCollector.create({
				policies: PERMIT_ALL,
				principal: { attributes: { dept: 7 } },
			}),
		).rejects.toThrow(/principal\.attributes\.dept/);
	});

	it("refuses a non-string engine", async () => {
		await expect(
			CedarPolicyRuleCollector.create({ policies: PERMIT_ALL, engine: 7 as unknown as string }),
		).rejects.toThrow(/CedarPolicyRuleCollector: engine must be a non-empty string/);
	});

	it("refuses an engine nobody registered, listing what is", async () => {
		await expect(
			CedarPolicyRuleCollector.create({ policies: PERMIT_ALL, engine: "opa" }),
		).rejects.toThrow(
			// "http" is registered by cedar's own entry point, which the scripted
			// engine helper imports; the three fakes follow in registration order.
			/CedarPolicyRuleCollector: engine "opa" is not a registered Cedar engine \(registered: http, wasm, fake-async, fake-async-vouching\)/,
		);
	});
});

describe("CedarPolicyRuleCollector — engine selection and what the engine receives", () => {
	it("uses the preferred registered engine when config names none", async () => {
		const before = sync.loads.length;
		await collectSync({ policies: PERMIT_ALL });
		expect(sync.loads).toHaveLength(before + 1);
	});

	it("uses the named engine when config names one", async () => {
		const before = async.loads.length;
		await collectAsync({ policies: PERMIT_ALL });
		expect(async.loads).toHaveLength(before + 1);
	});

	it("hands the engine the policy source as loaded — files and concatenation", async () => {
		await collectSync({ policies: PERMIT_ALL });
		const files = [{ name: "policies", source: "policies (inline)", text: PERMIT_ALL }];
		expect(sync.loads.at(-1)).toEqual({
			files,
			text: PERMIT_ALL,
			description: "inline policies",
			revision: computePolicyRevision(files),
		});
	});

	it("hands the policy set the request built from attrs — entities inline", async () => {
		const rule = await collectSync({
			policies: PERMIT_ALL,
			principal: {
				attributes: { dept: "department", title: "jobTitle", level: "level" },
				parents: { Group: "groups" },
			},
			resource: { attributes: { owner: { attribute: "resourceOwner", entityType: "User" } } },
			context: { mfa: "mfaVerified", ip: "clientIp" },
		});
		rule.verify(
			attrsWith([
				["department", "eng"],
				// Unrepresentable values are omitted, never sent: Cedar has no null
				// (its JSON formats fail the whole request on one) and no fraction.
				["jobTitle", null],
				["level", 1.5],
				["groups", ["admins"]],
				["resourceOwner", "alice"],
				["mfaVerified", true],
				["clientIp", null],
			]),
		);
		expect(sync.requests.at(-1)).toEqual({
			principal: { type: "User", id: "alice" },
			action: { type: "Action", id: "read" },
			resource: { type: "Document", id: "42" },
			context: { mfa: true },
			entities: [
				{
					uid: { type: "User", id: "alice" },
					attrs: { dept: "eng" },
					parents: [{ type: "Group", id: "admins" }],
				},
				{
					uid: { type: "Document", id: "42" },
					attrs: { owner: { __entity: { type: "User", id: "alice" } } },
					parents: [],
				},
			],
		});
	});
});

describe("CedarPolicyRuleCollector — rule metadata", () => {
	it("returns one rule in the configured group with the fixed code, for either kind", async () => {
		for (const rule of [
			await collectSync({ policies: PERMIT_ALL, ruleType: "authz-cedar" }),
			await collectAsync({ policies: PERMIT_ALL, ruleType: "authz-cedar" }),
		]) {
			expect(rule.ruleType).toBe("authz-cedar");
			expect(rule.code).toBe("cedar_deny");
			expect(rule.message).toBe("Denied by Cedar policy");
		}
	});
});

describe("CedarPolicyRuleCollector — answer interpretation", () => {
	it("passes on allow", async () => {
		const rule = await collectSync({ policies: PERMIT_ALL });
		expect(rule.verify(attrsWith())).toBe(true);
	});

	it("fails on a determining forbid", async () => {
		sync.answer = () => FORBIDDEN;
		const rule = await collectSync({ policies: PERMIT_ALL });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("denies by default when no policy determines the request", async () => {
		sync.answer = () => UNDETERMINED;
		const rule = await collectSync({ policies: PERMIT_ALL });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("abstains when the deployment asks for it — the migration posture", async () => {
		sync.answer = () => UNDETERMINED;
		const rule = await collectSync({ policies: PERMIT_ALL, onNoDeterminingPolicy: "abstain" });
		expect(rule.verify(attrsWith())).toBe(true);
	});

	it("denies when the deployment spells the default out", async () => {
		sync.answer = () => UNDETERMINED;
		const rule = await collectSync({ policies: PERMIT_ALL, onNoDeterminingPolicy: "deny" });
		expect(rule.verify(attrsWith())).toBe(false);
	});

	it("leaves a determining permit alone under either setting", async () => {
		for (const onNoDeterminingPolicy of ["abstain", "deny"] as const) {
			const rule = await collectSync({ policies: PERMIT_ALL, onNoDeterminingPolicy });
			expect(rule.verify(attrsWith())).toBe(true);
		}
	});

	it("denies and logs on evaluation errors even under abstain — the fail-open trap", async () => {
		const { logger, error } = fakeLogger();
		sync.answer = () => ({
			decision: "deny",
			reason: [],
			errors: ['policy0: `User::"alice"` does not have the attribute `dept`'],
		});
		const rule = await collectSync(
			{ policies: PERMIT_ALL, onNoDeterminingPolicy: "abstain" },
			logger,
		);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/does not have the attribute/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/"engine":"wasm"/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/"ruleType":"cedar"/);
	});

	it("denies when errors accompany a top-level allow — an erroring forbid stops forbidding", async () => {
		const { logger, error } = fakeLogger();
		sync.answer = () => ({ decision: "allow", reason: ["policy0"], errors: ["policy1: boom"] });
		const rule = await collectSync({ policies: PERMIT_ALL }, logger);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
	});

	it("denies and logs when the call itself fails — never an abstention", async () => {
		const { logger, error } = fakeLogger();
		sync.answer = () => {
			throw new CedarEngineError("wasm instance gone");
		};
		const rule = await collectSync(
			{ policies: PERMIT_ALL, onNoDeterminingPolicy: "abstain" },
			logger,
		);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/authorization call failed/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/wasm instance gone/);
	});

	it("stays silent on the error branches when asked to", async () => {
		const { logger, error } = fakeLogger();
		sync.answer = () => ({ decision: "deny", reason: [], errors: ["policy0: boom"] });
		const rule = await collectSync({ policies: PERMIT_ALL, logEvaluationErrors: false }, logger);
		expect(rule.verify(attrsWith())).toBe(false);
		expect(error).not.toHaveBeenCalled();
	});

	it("denies on a missing principal id without asking the engine", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectSync({ policies: PERMIT_ALL }, logger);
		const attrs = attrsWith();
		attrs.delete("userId");
		expect(rule.verify(attrs)).toBe(false);
		expect(sync.requests).toHaveLength(0);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/principal id/);
	});

	it("denies on malformed parents rather than silently un-membering", async () => {
		const { logger, error } = fakeLogger();
		const rule = await collectSync(
			{ policies: PERMIT_ALL, principal: { parents: { Group: "groups" } } },
			logger,
		);
		expect(rule.verify(attrsWith([["groups", [1, 2]]]))).toBe(false);
		expect(sync.requests).toHaveLength(0);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/groups/);
	});
});

describe("CedarPolicyRuleCollector — an asynchronous engine yields an AsyncRule", () => {
	it("interprets the answer by the same table, through decide", async () => {
		const rule = await collectAsync({ policies: PERMIT_ALL });
		expect(await rule.decide(attrsWith(), NEVER_ABORTS)).toBe(true);
		async.answer = () => FORBIDDEN;
		expect(await rule.decide(attrsWith(), NEVER_ABORTS)).toBe(false);
		async.answer = () => UNDETERMINED;
		expect(await rule.decide(attrsWith(), NEVER_ABORTS)).toBe(false);
	});

	it("hands the engine the signal it was given", async () => {
		const controller = new AbortController();
		let handed: AbortSignal | undefined;
		async.answer = (_request, signal) => {
			handed = signal;
			return ALLOW;
		};
		const rule = await collectAsync({ policies: PERMIT_ALL });
		await rule.decide(attrsWith(), controller.signal);
		expect(handed).toBe(controller.signal);
	});

	it("denies and logs on a rejected call — never an abstention", async () => {
		const { logger, error } = fakeLogger();
		async.answer = () => {
			throw new CedarEngineError("engine unreachable");
		};
		const rule = await collectAsync({ policies: PERMIT_ALL }, logger);
		expect(await rule.decide(attrsWith(), NEVER_ABORTS)).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/engine unreachable/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/"engine":"fake-async"/);
	});

	it("rejects with the signal's reason when the call was aborted, rather than denying (review)", async () => {
		// The evaluator's timeout and the caller's abort both arrive as the
		// signal's reason. Folded into a logged deny, a timeout read as
		// `cedar_deny` and a caller that left read as an engine outage.
		const { logger, error } = fakeLogger();
		// The async engine awaits what `answer` returns, so a pending promise is
		// what a slow agent looks like from here.
		async.answer = (_request, signal) =>
			new Promise((_resolve, reject) => {
				signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
			}) as unknown as CedarDecision;
		const rule = await collectAsync({ policies: PERMIT_ALL }, logger);
		const controller = new AbortController();
		const reason = new Error("the caller closed the connection");
		const pending = rule.decide(attrsWith(), controller.signal);
		controller.abort(reason);
		await expect(pending).rejects.toBe(reason);
		expect(error).not.toHaveBeenCalled();
	});

	it("denies on attributes that cannot supply the request, without asking the engine", async () => {
		const rule = await collectAsync({ policies: PERMIT_ALL, logEvaluationErrors: false });
		expect(await rule.decide(new Map(), NEVER_ABORTS)).toBe(false);
		expect(async.requests).toHaveLength(0);
	});
});

describe("CedarPolicyRuleCollector — layered PDP through core evaluate", () => {
	const tsRule: Rule = {
		ruleType: "scope",
		code: "invalid_scope",
		message: "Insufficient scope",
		verify: (attrs) => attrs.get("scopeOk") === true,
	};

	it("ANDs the cedar group with a TypeScript group, whichever kind the engine yields", async () => {
		for (const cedarRule of [
			await collectSync({ policies: PERMIT_ALL }),
			await collectAsync({ policies: PERMIT_ALL }),
		]) {
			const both = await evaluate(attrsWith([["scopeOk", true]]), [cedarRule, tsRule]);
			expect(both.decision).toBe("allow");

			// Cedar permits, the TS group refuses: AND composes toward strictness.
			const tsDenies = await evaluate(attrsWith([["scopeOk", false]]), [cedarRule, tsRule]);
			expect(tsDenies.decision).toBe("deny");
		}
	});

	it("reports the cedar group by its code when the engine forbids", async () => {
		sync.answer = () => FORBIDDEN;
		const cedarRule = await collectSync({ policies: PERMIT_ALL });
		const result = await evaluate(attrsWith([["scopeOk", true]]), [cedarRule, tsRule]);
		expect(result).toMatchObject({ decision: "deny", code: "cedar_deny" });
	});
});

/*
 * #244: what the rule reports about the evaluation behind each answer.
 *
 * Every `false` below is the same `cedar_deny` to the evaluator, and has to
 * be — the rule fails closed. What differs is whether a policy produced it,
 * and the rule says so through the reporter core hands it for that one call.
 * It still ANSWERS a boolean: see "asked without a reporter".
 * The answer table, again, with the column the audit record needs:
 *
 * | the rule answered because | evaluation.status | revision |
 * | --- | --- | --- |
 * | Cedar answered, no errors (permit, forbid, or nothing determining) | completed | the engine's, when it vouches |
 * | Cedar answered with evaluation errors | failed | the engine's, when it vouches |
 * | the call itself failed | failed | null — nothing answered, so nothing vouched |
 * | the request could not be built | not_invoked | no key at all |
 */
describe("CedarPolicyRuleCollector — the evaluation behind an answer (#244)", () => {
	const REVISION = computePolicyRevision([{ name: "policies", text: PERMIT_ALL }]);
	const OTHER_POLICIES = "forbid(principal, action, resource);";
	const OTHER_REVISION = computePolicyRevision([{ name: "policies", text: OTHER_POLICIES }]);

	/** What a rule answered and what it reported — asked the way core asks, with a reporter. */
	type Asked = { passed: boolean; evaluation?: RuleEvaluation };
	const asked = (passed: boolean, evaluation: RuleEvaluation | undefined): Asked =>
		evaluation === undefined ? { passed } : { passed, evaluation };
	const ask = (rule: Rule, attrs: Attributes): Asked => {
		let evaluation: RuleEvaluation | undefined;
		const passed = rule.verify(attrs, (reported) => {
			evaluation = reported;
		});
		return asked(passed, evaluation);
	};
	const askAsync = async (rule: AsyncRule, attrs: Attributes): Promise<Asked> => {
		let evaluation: RuleEvaluation | undefined;
		const passed = await rule.decide(attrs, NEVER_ABORTS, (reported) => {
			evaluation = reported;
		});
		return asked(passed, evaluation);
	};

	describe("an engine that vouches for what it evaluated (in-process)", () => {
		it("reports a completed evaluation of the loaded revision on a permit", async () => {
			const rule = await collectSync({ policies: PERMIT_ALL });
			expect(ask(rule, attrsWith())).toEqual({
				passed: true,
				evaluation: { status: "completed", revision: REVISION },
			});
		});

		it("reports the same on a forbid — a policy-deny is a completed evaluation", async () => {
			sync.answer = () => FORBIDDEN;
			const rule = await collectSync({ policies: PERMIT_ALL });
			expect(ask(rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "completed", revision: REVISION },
			});
		});

		it.each([
			["deny", false],
			["abstain", true],
		] as const)(
			"reports completed when no policy determined the request, under %s",
			async (onNoDeterminingPolicy, passed) => {
				// Cedar ran to the end and found nothing to say: that is its answer,
				// not a failure to get one.
				sync.answer = () => UNDETERMINED;
				const rule = await collectSync({ policies: PERMIT_ALL, onNoDeterminingPolicy });
				expect(ask(rule, attrsWith())).toEqual({
					passed,
					evaluation: { status: "completed", revision: REVISION },
				});
			},
		);

		it("never claims a revision when the request could not be built — Cedar was not asked", async () => {
			const rule = await collectSync({ policies: PERMIT_ALL }, fakeLogger().logger);
			const attrs = attrsWith();
			attrs.delete("userId");
			const answer = ask(rule, attrs);
			expect(sync.requests).toHaveLength(0);
			expect(answer).toEqual({ passed: false, evaluation: { status: "not_invoked" } });
			expect(JSON.stringify(answer)).not.toContain("sha256:");
		});

		it("reports a failed evaluation when the call itself fails, vouching for nothing", async () => {
			sync.answer = () => {
				throw new CedarEngineError("wasm instance gone");
			};
			const rule = await collectSync({ policies: PERMIT_ALL }, fakeLogger().logger);
			expect(ask(rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
			});
		});

		it("reports a failed evaluation on Cedar's diagnostic errors, whatever the decision reads", async () => {
			const rule = await collectSync({ policies: PERMIT_ALL }, fakeLogger().logger);
			for (const decision of ["deny", "allow"] as const) {
				sync.answer = () => ({ decision, reason: ["policy0"], errors: ["policy1: boom"] });
				expect(ask(rule, attrsWith())).toEqual({
					passed: false,
					evaluation: { status: "failed", revision: REVISION },
				});
			}
		});

		it("answers equal attributes with an equal report — the evaluation is part of the answer", async () => {
			const rule = await collectSync({ policies: PERMIT_ALL });
			expect(ask(rule, attrsWith())).toEqual(ask(rule, attrsWith()));
		});

		it("names the revision of what was loaded, per collector", async () => {
			const one = await collectSync({ policies: PERMIT_ALL });
			const other = await collectSync({ policies: OTHER_POLICIES, ruleType: "cedar-other" });
			expect(ask(one, attrsWith()).evaluation).toEqual({
				status: "completed",
				revision: REVISION,
			});
			expect(ask(other, attrsWith()).evaluation).toEqual({
				status: "completed",
				revision: OTHER_REVISION,
			});
		});
	});

	describe("asked without a reporter — an evaluator that predates it", () => {
		/*
		 * The reason the evaluation is reported rather than returned. A mixed
		 * install — this package beside a server and core one release older —
		 * has the OLD `evaluate()` running this rule, and it reads the answer by
		 * truthiness. An answer carrying the evaluation is an object, and an
		 * object is truthy: every Cedar deny would have been an allow.
		 */
		const legacyReads = (answer: unknown): boolean => Boolean(answer);

		it("answers a plain boolean on every row of the table, so a deny stays a deny", async () => {
			const { logger } = fakeLogger();
			const rule = await collectSync({ policies: PERMIT_ALL }, logger);

			expect(rule.verify(attrsWith())).toBe(true);

			sync.answer = () => FORBIDDEN;
			expect(rule.verify(attrsWith())).toBe(false);
			expect(legacyReads(rule.verify(attrsWith()))).toBe(false);

			sync.answer = () => ({ decision: "allow", reason: ["policy0"], errors: ["policy1: boom"] });
			expect(legacyReads(rule.verify(attrsWith()))).toBe(false);

			sync.answer = () => {
				throw new CedarEngineError("wasm instance gone");
			};
			expect(legacyReads(rule.verify(attrsWith()))).toBe(false);

			const unbuilt = attrsWith();
			unbuilt.delete("userId");
			expect(legacyReads(rule.verify(unbuilt))).toBe(false);
		});

		it("does the same through decide", async () => {
			const rule = await collectAsync({ policies: PERMIT_ALL }, fakeLogger().logger);
			async.answer = () => FORBIDDEN;
			const answer = await rule.decide(attrsWith(), NEVER_ABORTS);
			expect(answer).toBe(false);
			expect(legacyReads(answer)).toBe(false);
		});
	});

	describe("an engine that does not say what it evaluated (remote)", () => {
		it("reports the revision as not established, and what was loaded apart from it", async () => {
			const rule = await collectAsync({ policies: PERMIT_ALL });
			expect(await askAsync(rule, attrsWith())).toEqual({
				passed: true,
				evaluation: { status: "completed", revision: null, loadedRevision: REVISION },
			});
		});

		it("reports not_invoked and failed by the same table", async () => {
			const rule = await collectAsync({ policies: PERMIT_ALL }, fakeLogger().logger);
			const attrs = attrsWith();
			attrs.delete("userId");
			expect(await askAsync(rule, attrs)).toEqual({
				passed: false,
				evaluation: { status: "not_invoked" },
			});

			async.answer = () => {
				throw new CedarEngineError("agent unreachable");
			};
			expect(await askAsync(rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
			});

			async.answer = () => ({ decision: "deny", reason: [], errors: ["policy0: boom"] });
			expect(await askAsync(rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
			});
		});
	});

	describe("the confirmation contract — an answer that names a revision", () => {
		const collectVouching = async (config: Record<string, unknown>, logger?: Logger) => {
			const collector = await CedarPolicyRuleCollector.create(
				{ ...config, engine: "fake-async-vouching" },
				logger ? { logger } : undefined,
			);
			return (await collector.collect(context))[0] as AsyncRule;
		};

		it("reports the revision as evaluated when it is the one that was loaded", async () => {
			const rule = await collectVouching({ policies: PERMIT_ALL });
			expect(await askAsync(rule, attrsWith())).toEqual({
				passed: true,
				evaluation: { status: "completed", revision: REVISION },
			});
		});

		it.each([
			["another policy set's", OTHER_REVISION],
			["not a revision at all", "/etc/verifier/policies"],
			["something that is not a string", null],
		])(
			"fails closed and logs when the engine names %s — and never repeats it",
			async (_name, named) => {
				// The engine holds a set this verifier did not load: a permit from it
				// is a permit from somebody else's policies.
				const { logger, error } = fakeLogger();
				asyncVouching.answer = () => ({ ...ALLOW, revision: named as string });
				const rule = await collectVouching({ policies: PERMIT_ALL }, logger);
				const answer = await askAsync(rule, attrsWith());
				expect(answer).toEqual({
					passed: false,
					evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
				});
				if (typeof named === "string") expect(JSON.stringify(answer)).not.toContain(named);
				expect(error).toHaveBeenCalledOnce();
				expect(JSON.stringify(error.mock.calls[0])).toMatch(/revision/);
			},
		);

		it("logs a mismatch even with logEvaluationErrors off — it is not an evaluation error", async () => {
			// `logEvaluationErrors = false` silences a policy reading a missing
			// attribute. An engine answering from a policy set this verifier did
			// not load is a fault of the deployment, and is never silent.
			const { logger, error } = fakeLogger();
			asyncVouching.answer = () => ({ ...ALLOW, revision: OTHER_REVISION });
			const rule = await collectVouching(
				{ policies: PERMIT_ALL, logEvaluationErrors: false },
				logger,
			);
			expect((await askAsync(rule, attrsWith())).passed).toBe(false);
			expect(error).toHaveBeenCalledOnce();
		});
	});

	describe("the loaded revision is the collector's own reading, taken before the engine has the source", () => {
		it("is not what an engine rewrote on the source during load", async () => {
			// `PolicySource` is a plain object and `load` is handed it. An engine
			// that rewrote `revision` there — a bug, or worse — must not thereby
			// choose what this collector reports as loaded, or have its own
			// answers confirmed against the rewrite.
			const rewriting = scriptedEngine("fake-rewriting", false, { confirmsRevision: true });
			const load = rewriting.load.bind(rewriting);
			rewriting.load = (source, loadContext) => {
				(source as { revision: string }).revision = OTHER_REVISION;
				return load(source, loadContext);
			};
			registerCedarEngine(rewriting);

			const { logger, error } = fakeLogger();
			const collector = await CedarPolicyRuleCollector.create(
				{ policies: PERMIT_ALL, engine: "fake-rewriting" },
				{ logger },
			);
			const [rule] = await collector.collect(context);
			// The engine now vouches for OTHER_REVISION; the collector loaded
			// REVISION. That is a mismatch, and it fails closed.
			expect(ask(rule as Rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
			});
			expect(error).toHaveBeenCalledOnce();
		});
	});

	describe("requireConfirmedRevision — a deployment that must be able to say which policies decided", () => {
		it("refuses at boot an engine that does not vouch, naming the key and the engine", async () => {
			const before = async.loads.length;
			await expect(
				CedarPolicyRuleCollector.create({
					policies: PERMIT_ALL,
					engine: "fake-async",
					requireConfirmedRevision: true,
				}),
			).rejects.toThrow(/requireConfirmedRevision.*"fake-async"/s);
			// Refused before `load`, which has side effects on a remote engine.
			expect(async.loads).toHaveLength(before);
		});

		it("boots over an engine that vouches", async () => {
			await expect(
				collectSync({ policies: PERMIT_ALL, requireConfirmedRevision: true }),
			).resolves.toBeDefined();
		});

		it("refuses a non-boolean value", async () => {
			await expect(
				CedarPolicyRuleCollector.create({
					policies: PERMIT_ALL,
					requireConfirmedRevision: "yes",
				} as never),
			).rejects.toThrow(/requireConfirmedRevision must be a boolean/);
		});

		it("denies and logs an answer that arrives unvouched after all — the declaration was wrong", async () => {
			const { logger, error } = fakeLogger();
			sync.answer = () => ({ ...ALLOW, revision: undefined });
			const rule = await collectSync(
				{ policies: PERMIT_ALL, requireConfirmedRevision: true },
				logger,
			);
			expect(ask(rule, attrsWith())).toEqual({
				passed: false,
				evaluation: { status: "failed", revision: null, loadedRevision: REVISION },
			});
			expect(error).toHaveBeenCalledOnce();
		});

		it("logs that deny even with logEvaluationErrors off", async () => {
			const { logger, error } = fakeLogger();
			sync.answer = () => ({ ...ALLOW, revision: undefined });
			const rule = await collectSync(
				{ policies: PERMIT_ALL, requireConfirmedRevision: true, logEvaluationErrors: false },
				logger,
			);
			expect(ask(rule, attrsWith()).passed).toBe(false);
			expect(error).toHaveBeenCalledOnce();
		});

		it("lets the same unvouched answer through when the deployment did not ask", async () => {
			sync.answer = () => ({ ...ALLOW, revision: undefined });
			const rule = await collectSync({ policies: PERMIT_ALL });
			expect(ask(rule, attrsWith())).toEqual({
				passed: true,
				evaluation: { status: "completed", revision: null, loadedRevision: REVISION },
			});
		});
	});

	describe("through core evaluate", () => {
		it("lands each collector's evaluation on its own outcome, under concurrent decisions", async () => {
			const one = await collectSync({ policies: PERMIT_ALL, ruleType: "cedar-a" });
			const other = await collectAsync({ policies: OTHER_POLICIES, ruleType: "cedar-b" });
			const decisions = await Promise.all(
				Array.from({ length: 8 }, () => evaluate(attrsWith(), [one, other])),
			);
			for (const decision of decisions) {
				const byType = new Map(decision.reason.groups.map((group) => [group.ruleType, group]));
				expect(byType.get("cedar-a")?.evaluated[0].evaluation).toEqual({
					status: "completed",
					revision: REVISION,
				});
				expect(byType.get("cedar-b")?.evaluated[0].evaluation).toEqual({
					status: "completed",
					revision: null,
					loadedRevision: OTHER_REVISION,
				});
			}
		});

		it("keeps a denial Cedar never produced apart from one it did, under the same code", async () => {
			const rule = await collectSync({ policies: PERMIT_ALL }, fakeLogger().logger);
			sync.answer = () => FORBIDDEN;
			const denied = await evaluate(attrsWith(), [rule]);
			const unbuilt = attrsWith();
			unbuilt.delete("userId");
			const notInvoked = await evaluate(unbuilt, [rule]);

			for (const decision of [denied, notInvoked]) {
				expect(decision).toMatchObject({ decision: "deny", code: "cedar_deny" });
			}
			expect(denied.reason.groups[0].evaluated[0].evaluation).toEqual({
				status: "completed",
				revision: REVISION,
			});
			expect(notInvoked.reason.groups[0].evaluated[0].evaluation).toEqual({
				status: "not_invoked",
			});
		});
	});
});
