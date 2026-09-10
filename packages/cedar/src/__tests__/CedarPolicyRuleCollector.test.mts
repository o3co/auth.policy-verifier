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
} from "@o3co/auth.policy-verifier.core";
import { evaluate, isAsyncRule } from "@o3co/auth.policy-verifier.core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	CedarPolicyRuleCollector,
	type NoDeterminingPolicy,
} from "../CedarPolicyRuleCollector.mjs";
import { CedarEngineError, registerCedarEngine } from "../engine.mjs";
import { ALLOW, FORBIDDEN, scriptedEngine, UNDETERMINED } from "./scriptedEngine.mjs";

// "wasm" so that the engine-less default resolves here, as it does in a
// deployment that imported the wasm package; the asynchronous one under a
// name no real engine takes, selected explicitly.
const sync = scriptedEngine("wasm", false);
const async = scriptedEngine("fake-async", true);
registerCedarEngine(sync);
registerCedarEngine(async);

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
	sync.answer = () => ALLOW;
	async.answer = () => ALLOW;
	sync.requests.length = 0;
	async.requests.length = 0;
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
			// engine helper imports; the two fakes follow in registration order.
			/CedarPolicyRuleCollector: engine "opa" is not a registered Cedar engine \(registered: http, wasm, fake-async\)/,
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
		expect(sync.loads.at(-1)).toEqual({
			files: [{ source: "policies (inline)", text: PERMIT_ALL }],
			text: PERMIT_ALL,
			description: "inline policies",
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
		const rule = await collectAsync(
			{ policies: PERMIT_ALL, onNoDeterminingPolicy: "abstain" },
			logger,
		);
		expect(await rule.decide(attrsWith(), NEVER_ABORTS)).toBe(false);
		expect(error).toHaveBeenCalledOnce();
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/engine unreachable/);
		expect(JSON.stringify(error.mock.calls[0])).toMatch(/"engine":"fake-async"/);
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
