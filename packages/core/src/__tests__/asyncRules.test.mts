// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #225: a rule whose answer comes from I/O — an out-of-process policy engine —
 * cannot be a `Rule`, whose `verify` is synchronous and, by contract, does no
 * I/O. `AsyncRule.decide(attrs, signal)` is the additive form: same grouping,
 * same reporting, same "a function of attrs and nothing else", with a deadline.
 * `evaluate()` is the one evaluator, and it runs both kinds after both
 * collects are done — asynchronous itself for that reason alone.
 */
import { describe, expect, it, vi } from "vitest";
import {
	DEFAULT_COLLECTOR_TIMEOUT_MS,
	DEFAULT_RULE_TIMEOUT_MS,
	MAX_TIMER_MS,
} from "../collectorLimits.mjs";
import { RuleTimeoutError } from "../errors.mjs";
import { evaluate } from "../evaluate.mjs";
import {
	type AnyRule,
	type AsyncRule,
	type Attributes,
	isAsyncRule,
	type Rule,
} from "../types.mjs";

const sync = (ruleType: string, code: string, result: boolean): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: () => result,
});

const async = (
	ruleType: string,
	code: string,
	result: boolean | (() => Promise<boolean>),
): AsyncRule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	decide: typeof result === "function" ? result : async () => result,
});

const attrs: Attributes = new Map([["scopes", ["read:project"]]]);

describe("isAsyncRule", () => {
	it("tells the two kinds apart by the presence of decide", () => {
		expect(isAsyncRule(sync("scope", "a", true))).toBe(false);
		expect(isAsyncRule(async("scope", "a", true))).toBe(true);
	});
});

describe("evaluate — asynchronous rules", () => {
	it("allows when an async rule passes", async () => {
		const result = await evaluate(attrs, [async("cedar", "cedar_deny", true)]);
		expect(result.decision).toBe("allow");
		expect(result.reason.groups[0]).toMatchObject({
			ruleType: "cedar",
			passed: true,
			satisfiedBy: { code: "cedar_deny", passed: true },
		});
	});

	it("denies with the async rule's own code and message when it fails", async () => {
		const result = await evaluate(attrs, [async("cedar", "cedar_deny", false)]);
		expect(result).toMatchObject({
			decision: "deny",
			code: "cedar_deny",
			message: "Failed: cedar_deny",
		});
	});

	it("keeps default-deny on an empty rule set, and the allow opt-out", async () => {
		expect((await evaluate(attrs, [])).decision).toBe("deny");
		expect((await evaluate(attrs, [], { onEmptyRuleSet: "allow" })).decision).toBe("allow");
	});

	it("ANDs across groups whichever kind each group holds", async () => {
		const rules: AnyRule[] = [
			sync("scope", "invalid_scope", true),
			async("cedar", "cedar_deny", false),
		];
		const result = await evaluate(attrs, rules);
		expect(result).toMatchObject({ decision: "deny", code: "cedar_deny" });
		expect(result.reason.groups.map((g) => [g.ruleType, g.passed])).toEqual([
			["scope", true],
			["cedar", false],
		]);
	});

	it("ORs within a group and stops at the first passing rule — a later async rule never runs", async () => {
		const later = vi.fn(async () => true);
		const rules: AnyRule[] = [async("cedar", "first", true), async("cedar", "second", later)];
		const result = await evaluate(attrs, rules);
		expect(result.decision).toBe("allow");
		expect(later).not.toHaveBeenCalled();
		expect(result.reason.groups[0].evaluated.map((r) => r.code)).toEqual(["first"]);
	});

	it("runs the alternatives of one group in order, one at a time", async () => {
		const order: string[] = [];
		const slow = (name: string, answer: boolean) =>
			async("cedar", name, async () => {
				order.push(`${name}:start`);
				await new Promise((r) => setTimeout(r, 5));
				order.push(`${name}:end`);
				return answer;
			});
		await evaluate(attrs, [slow("a", false), slow("b", true)]);
		expect(order).toEqual(["a:start", "a:end", "b:start", "b:end"]);
	});

	it("hands each async rule the attributes and a signal", async () => {
		const seen = vi.fn(async (a: unknown, s: unknown) => {
			expect(a).toBe(attrs);
			expect(s).toBeInstanceOf(AbortSignal);
			return true;
		});
		await evaluate(attrs, [async("cedar", "x", seen as never)]);
		expect(seen).toHaveBeenCalledTimes(1);
	});

	it("propagates a rejection unchanged — a fault, not a deny", async () => {
		const boom = new Error("engine exploded");
		await expect(
			evaluate(attrs, [
				async("cedar", "x", async () => {
					throw boom;
				}),
			]),
		).rejects.toBe(boom);
	});
});

describe("evaluate — the deadline (#225)", () => {
	it("defaults the per-rule budget to the collector timeout's value", () => {
		expect(DEFAULT_RULE_TIMEOUT_MS).toBe(2_000);
		expect(DEFAULT_RULE_TIMEOUT_MS).toBe(DEFAULT_COLLECTOR_TIMEOUT_MS);
	});

	it("rejects with RuleTimeoutError when an async rule does not answer in time, and aborts its signal", async () => {
		let handed: AbortSignal | undefined;
		const never = async("cedar", "cedar_deny", async () => {
			return new Promise<boolean>(() => {});
		});
		never.decide = async (_attrs, signal) => {
			handed = signal;
			return new Promise<boolean>(() => {});
		};
		await expect(evaluate(attrs, [never], { ruleTimeoutMs: 20 })).rejects.toMatchObject({
			name: "RuleTimeoutError",
			ruleType: "cedar",
			code: "cedar_deny",
			timeoutMs: 20,
		});
		expect(handed?.aborted).toBe(true);
		expect(handed?.reason).toBeInstanceOf(RuleTimeoutError);
	});

	it("answers the abort reason, not the rule's own abort error, when a rule honours its signal", async () => {
		// The shape `fetch` gives: on abort the rule rejects with an AbortError of
		// its own, in the same tick the deadline (or the caller) aborted it.
		const abortAware = async("cedar", "cedar_deny", async () => true);
		abortAware.decide = (_attrs, signal) =>
			new Promise<boolean>((_resolve, reject) => {
				signal.addEventListener(
					"abort",
					() => reject(new DOMException("The operation was aborted", "AbortError")),
					{ once: true },
				);
			});
		await expect(evaluate(attrs, [abortAware], { ruleTimeoutMs: 20 })).rejects.toBeInstanceOf(
			RuleTimeoutError,
		);

		const controller = new AbortController();
		const reason = new Error("caller left");
		const pending = evaluate(attrs, [abortAware], { signal: controller.signal });
		controller.abort(reason);
		await expect(pending).rejects.toBe(reason);
	});

	it("rejects with the caller's reason when the caller's signal aborts first", async () => {
		const controller = new AbortController();
		const reason = new Error("caller left");
		const never = async("cedar", "x", async () => new Promise<boolean>(() => {}));
		const pending = evaluate(attrs, [never], { signal: controller.signal });
		controller.abort(reason);
		await expect(pending).rejects.toBe(reason);
	});

	it("refuses an unusable budget before running anything", async () => {
		const ran = vi.fn(async () => true);
		for (const ruleTimeoutMs of [0, -1, 1.5, MAX_TIMER_MS + 1, Number.NaN]) {
			await expect(evaluate(attrs, [async("cedar", "x", ran)], { ruleTimeoutMs })).rejects.toThrow(
				/ruleTimeoutMs/,
			);
		}
		expect(ran).not.toHaveBeenCalled();
	});
});
