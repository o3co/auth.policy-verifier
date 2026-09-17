// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #244: a rule backed by a policy evaluator has more to say than pass / fail —
 * whether the evaluator ran at all, and against which policy snapshot. That is
 * a fact about ONE invocation, so it cannot live on the rule, which answers
 * concurrent decisions.
 *
 * The channel is a reporter the evaluator hands the rule for that one
 * invocation: `verify(attrs, report)` / `decide(attrs, signal, report)`. The
 * rule still answers a boolean. That is the point of the shape: an evaluator
 * that knows nothing of reports — an older copy of core in a mixed install, a
 * composite rule calling `verify` itself — passes no reporter and reads a
 * boolean, so it decides correctly and merely records no evaluation. An answer
 * that carried the evaluation would have been an object, and an object is
 * truthy: every such evaluator would have read a deny as a pass.
 *
 * What is pinned here is that channel, engine-neutrally: what may be reported,
 * that it lands on the outcome of the invocation it belongs to and on no
 * other, and that nothing unbounded crosses — a rule is third-party code and
 * what it reports ends up on the wire and in the audit log.
 */
import { describe, expect, it } from "vitest";
import { RuleTimeoutError } from "../errors.mjs";
import { evaluate } from "../evaluate.mjs";
import { FailureRecord } from "../failureSource.mjs";
import {
	type AnyRule,
	type AsyncRule,
	type Attributes,
	POLICY_REVISION_MAX_LENGTH,
	type ReportRuleEvaluation,
	type Rule,
	type RuleEvaluation,
} from "../types.mjs";

const REVISION_A = `sha256:${"a".repeat(64)}`;
const REVISION_B = `sha256:${"b".repeat(64)}`;

const attrs: Attributes = new Map();

/** What a rule does with the reporter it is handed, and what it answers. */
type Behaviour = (report: ReportRuleEvaluation | undefined) => boolean;

const sync = (ruleType: string, code: string, behave: Behaviour): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: (_attrs, report) => behave(report),
});

const async = (ruleType: string, code: string, behave: Behaviour): AsyncRule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	async: true,
	decide: async (_attrs, _signal, report) => behave(report),
});

/** A rule that reports `evaluation` and then answers `passed`. */
const reporting =
	(passed: boolean, evaluation: RuleEvaluation): Behaviour =>
	(report) => {
		report?.(evaluation);
		return passed;
	};

/** The one outcome of a single-rule decision. */
async function outcomeOf(rule: AnyRule) {
	const decision = await evaluate(attrs, [rule]);
	expect(decision.reason.groups).toHaveLength(1);
	expect(decision.reason.groups[0].evaluated).toHaveLength(1);
	return { decision, outcome: decision.reason.groups[0].evaluated[0] };
}

describe("evaluate — what a rule reports about one invocation", () => {
	it("hands verify a reporter, and carries what was reported onto the outcome", async () => {
		const evaluation: RuleEvaluation = { status: "completed", revision: REVISION_A };
		const { decision, outcome } = await outcomeOf(
			sync("cedar", "cedar_deny", reporting(true, evaluation)),
		);
		expect(decision.decision).toBe("allow");
		expect(outcome).toEqual({
			code: "cedar_deny",
			message: "Failed: cedar_deny",
			passed: true,
			evaluation,
		});
	});

	it("carries it on a failing answer too — a policy-deny was evaluated as much as a permit", async () => {
		const evaluation: RuleEvaluation = { status: "completed", revision: REVISION_A };
		const { decision, outcome } = await outcomeOf(
			sync("cedar", "cedar_deny", reporting(false, evaluation)),
		);
		expect(decision.decision).toBe("deny");
		expect(outcome).toMatchObject({ passed: false, evaluation });
	});

	it("hands decide a reporter after its signal, and carries the report the same way", async () => {
		const evaluation: RuleEvaluation = {
			status: "completed",
			revision: null,
			loadedRevision: REVISION_A,
		};
		const { outcome } = await outcomeOf(async("cedar", "cedar_deny", reporting(true, evaluation)));
		expect(outcome.evaluation).toEqual(evaluation);
	});

	it("reports no evaluation key for a rule that reports nothing", async () => {
		const { outcome } = await outcomeOf(sync("scope", "invalid_scope", () => true));
		expect(Object.keys(outcome)).toEqual(["code", "message", "passed"]);
	});

	it("names the satisfying rule's evaluation on satisfiedBy, which is the same outcome", async () => {
		const decision = await evaluate(attrs, [
			sync("cedar", "cedar_deny", reporting(true, { status: "completed", revision: REVISION_A })),
		]);
		const group = decision.reason.groups[0];
		expect(group.passed).toBe(true);
		if (group.passed) {
			expect(group.satisfiedBy).toBe(group.evaluated.at(-1));
			expect(group.satisfiedBy.evaluation).toEqual({ status: "completed", revision: REVISION_A });
		}
	});

	it("keeps each source's evaluation on its own outcome across groups", async () => {
		// Two policy sources in one decision (#244: a single revision must not be
		// reported as though it described every rule that took part).
		const decision = await evaluate(attrs, [
			sync("cedar-a", "cedar_deny", reporting(true, { status: "completed", revision: REVISION_A })),
			sync("scope", "invalid_scope", () => true),
			sync(
				"cedar-b",
				"cedar_deny",
				reporting(false, { status: "completed", revision: REVISION_B }),
			),
		]);
		const byType = new Map(decision.reason.groups.map((group) => [group.ruleType, group]));
		expect(byType.get("cedar-a")?.evaluated[0].evaluation).toEqual({
			status: "completed",
			revision: REVISION_A,
		});
		expect(byType.get("scope")?.evaluated[0]).not.toHaveProperty("evaluation");
		expect(byType.get("cedar-b")?.evaluated[0].evaluation).toEqual({
			status: "completed",
			revision: REVISION_B,
		});
	});

	it("keeps alternatives of one OR group apart: the one that refused, and the one that passed", async () => {
		const decision = await evaluate(attrs, [
			sync("cedar", "cedar_deny", reporting(false, { status: "not_invoked" })),
			sync("cedar", "cedar_deny", reporting(true, { status: "completed", revision: REVISION_B })),
		]);
		expect(decision.decision).toBe("allow");
		expect(decision.reason.groups[0].evaluated).toEqual([
			{
				code: "cedar_deny",
				message: "Failed: cedar_deny",
				passed: false,
				evaluation: { status: "not_invoked" },
			},
			{
				code: "cedar_deny",
				message: "Failed: cedar_deny",
				passed: true,
				evaluation: { status: "completed", revision: REVISION_B },
			},
		]);
	});

	it("gives each invocation its own reporter, so concurrent decisions cannot take each other's", async () => {
		// One rule object, asked by six decisions in flight at once, reporting a
		// different revision on every call.
		let calls = 0;
		const rule = async("cedar", "cedar_deny", (report) => {
			report?.({ status: "completed", revision: calls++ % 2 === 0 ? REVISION_A : REVISION_B });
			return true;
		});
		const decisions = await Promise.all(Array.from({ length: 6 }, () => evaluate(attrs, [rule])));
		expect(decisions.map((d) => d.reason.groups[0].evaluated[0].evaluation)).toEqual(
			[REVISION_A, REVISION_B, REVISION_A, REVISION_B, REVISION_A, REVISION_B].map((revision) => ({
				status: "completed",
				revision,
			})),
		);
	});

	it("keeps a frozen copy, so a rule that reuses one evaluation object cannot rewrite a decision", async () => {
		const shared = { status: "completed", revision: REVISION_A } as {
			status: "completed";
			revision: string;
		};
		const { outcome } = await outcomeOf(sync("cedar", "cedar_deny", reporting(true, shared)));
		shared.revision = REVISION_B;
		expect(outcome.evaluation).toEqual({ status: "completed", revision: REVISION_A });
		expect(Object.isFrozen(outcome.evaluation)).toBe(true);
	});

	it("ignores a report that arrives after the answer — the decision is already made", async () => {
		let late: (() => void) | undefined;
		const rule = async("cedar", "cedar_deny", (report) => {
			late = () => report?.({ status: "completed", revision: REVISION_A });
			return true;
		});
		const { outcome } = await outcomeOf(rule);
		// Not a throw either: it would surface in the rule's own detached code,
		// as an unhandled rejection, for a decision nobody can change any more.
		expect(() => late?.()).not.toThrow();
		expect(outcome).not.toHaveProperty("evaluation");
	});

	it("carries nothing for a rule that reported and then never answered", async () => {
		const rule = async("cedar", "cedar_deny", () => true);
		rule.decide = (_attrs, _signal, report) => {
			report?.({ status: "completed", revision: REVISION_A });
			return new Promise<boolean>(() => {});
		};
		await expect(evaluate(attrs, [rule], { ruleTimeoutMs: 5 })).rejects.toThrow(RuleTimeoutError);
	});
});

describe("evaluate — what a rule may report", () => {
	const accepted: ReadonlyArray<[string, RuleEvaluation]> = [
		["not invoked", { status: "not_invoked" }],
		["completed against a vouched revision", { status: "completed", revision: REVISION_A }],
		["failed against a vouched revision", { status: "failed", revision: REVISION_A }],
		["completed, revision not established", { status: "completed", revision: null }],
		[
			"failed, revision not established, naming what was loaded",
			{ status: "failed", revision: null, loadedRevision: REVISION_A },
		],
	];
	it.each(accepted)("accepts: %s", async (_name, evaluation) => {
		const { outcome } = await outcomeOf(sync("cedar", "cedar_deny", reporting(false, evaluation)));
		expect(outcome.evaluation).toEqual(evaluation);
	});

	const refused: ReadonlyArray<[string, unknown]> = [
		["something that is not an object", "completed"],
		["an array", [{ status: "completed", revision: null }]],
		["null", null],
		["an unknown status", { status: "skipped", revision: null }],
		[
			"a revision on an evaluator that was never invoked",
			{ status: "not_invoked", revision: REVISION_A },
		],
		[
			"a loaded revision on an evaluator that was never invoked",
			{ status: "not_invoked", loadedRevision: REVISION_A },
		],
		["a completed evaluation that names no revision key", { status: "completed" }],
		[
			"a loaded revision beside a vouched one",
			{ status: "completed", revision: REVISION_A, loadedRevision: REVISION_A },
		],
		[
			"a revision that is a filesystem path",
			{ status: "completed", revision: "/etc/policies/prod" },
		],
		[
			"a revision that is policy text",
			{ status: "completed", revision: "permit(principal, action, resource);" },
		],
		[
			"a revision over the length bound",
			{ status: "completed", revision: `sha256:${"a".repeat(POLICY_REVISION_MAX_LENGTH)}` },
		],
		[
			"a key the contract does not name",
			{ status: "completed", revision: REVISION_A, policyText: "permit(…);" },
		],
	];
	it.each(refused)("refuses: %s", async (_name, evaluation) => {
		const failures = new FailureRecord();
		const rule = sync("cedar", "cedar_deny", reporting(false, evaluation as RuleEvaluation));
		const attempt = evaluate(attrs, [rule], { failures });
		await expect(attempt).rejects.toThrow(TypeError);
		// Attributed like any other fault of the rule's (#200), so the failure
		// line names the rule rather than reporting an anonymous 500.
		const error = await attempt.catch((cause: unknown) => cause);
		expect(failures.sourceOf(error)).toEqual({
			kind: "rule",
			ruleType: "cedar",
			code: "cedar_deny",
		});
	});

	it("refuses it even when the rule swallowed the refusal — a dropped report is a wrong record", async () => {
		const rule = sync("cedar", "cedar_deny", (report) => {
			try {
				report?.({ status: "completed", revision: "/etc/policies/prod" } as RuleEvaluation);
			} catch {
				// A rule that shrugs. The decision must not come out looking as if
				// it had reported nothing.
			}
			return false;
		});
		await expect(evaluate(attrs, [rule])).rejects.toThrow(TypeError);
	});

	it("refuses a second report for one invocation", async () => {
		const rule = sync("cedar", "cedar_deny", (report) => {
			report?.({ status: "completed", revision: REVISION_A });
			report?.({ status: "completed", revision: REVISION_B });
			return true;
		});
		await expect(evaluate(attrs, [rule])).rejects.toThrow(/more than once/);
	});

	it.each([
		["failed", { status: "failed", revision: REVISION_A }],
		["not_invoked", { status: "not_invoked" }],
	] as const)(
		"refuses a pass that reports its evaluator %s — that is not a policy's permit",
		async (_status, evaluation) => {
			// `failed` and `not_invoked` mean the rule failed closed. A rule that
			// passes while saying its evaluator did not answer has either decided
			// without its policies or reported wrongly; the audit record cannot tell
			// which, so neither is carried.
			await expect(
				evaluate(attrs, [sync("cedar", "cedar_deny", reporting(true, evaluation))]),
			).rejects.toThrow(TypeError);
		},
	);

	it("does not repeat a refused value in the error, which is logged", async () => {
		const secret = "permit(principal, action, resource);";
		const rule = sync(
			"cedar",
			"cedar_deny",
			reporting(false, { status: "completed", revision: secret }),
		);
		const error = await evaluate(attrs, [rule]).catch((cause: unknown) => cause);
		expect(error).toBeInstanceOf(TypeError);
		expect(String((error as Error).message)).not.toContain(secret);
	});

	it("refuses the same from an asynchronous rule", async () => {
		const rule = async(
			"cedar",
			"cedar_deny",
			reporting(false, { status: "skipped" } as unknown as RuleEvaluation),
		);
		await expect(evaluate(attrs, [rule])).rejects.toThrow(TypeError);
	});
});

/*
 * The answer itself is a boolean and nothing else. It used to be read by
 * truthiness, which is fail-open — a JavaScript rule that returns the attribute
 * it looked up (`attrs.get("role")`) passed whenever the attribute was set — and
 * it put that value on the wire as `passed`.
 */
describe("evaluate — a rule answers a boolean", () => {
	it.each([
		["a truthy string", "yes"],
		["a truthy number", 1],
		["a falsy number", 0],
		["an empty string", ""],
		["undefined", undefined],
		["null", null],
		// What carrying the evaluation in the answer would have looked like: an
		// object is truthy, so a deny of this shape read as a pass.
		["an object, even one that says it did not pass", { passed: false }],
		["a promise from a synchronous rule", Promise.resolve(false)],
	])("refuses an answer that is not a boolean: %s", async (_name, answer) => {
		const failures = new FailureRecord();
		const rule = sync("scope", "invalid_scope", () => answer as unknown as boolean);
		const attempt = evaluate(attrs, [rule], { failures });
		await expect(attempt).rejects.toThrow(TypeError);
		const error = await attempt.catch((cause: unknown) => cause);
		expect(failures.sourceOf(error)).toEqual({
			kind: "rule",
			ruleType: "scope",
			code: "invalid_scope",
		});
	});

	it("names the kind of a refused answer, never the answer — it may be an attribute value", async () => {
		const email = "alice@example.test";
		const rule = sync("scope", "invalid_scope", () => email as unknown as boolean);
		const error = await evaluate(attrs, [rule]).catch((cause: unknown) => cause);
		expect(error).toBeInstanceOf(TypeError);
		expect((error as Error).message).toMatch(/string/);
		expect((error as Error).message).not.toContain(email);
	});

	it("refuses the same from an asynchronous rule", async () => {
		const rule = async("scope", "invalid_scope", () => "yes" as unknown as boolean);
		await expect(evaluate(attrs, [rule])).rejects.toThrow(TypeError);
	});
});

/*
 * The reason for the shape, executed: an evaluator that predates the reporter
 * calls `verify(attrs)` and reads what comes back by truthiness. With the
 * evaluation in the answer it read every deny as a pass; with the reporter it
 * reads a boolean and is merely unaware of the evaluation.
 */
describe("a rule asked by an evaluator that passes no reporter", () => {
	const legacyEvaluate = (rules: Rule[]): boolean =>
		// v0.11.0's evaluateGroup, reduced to what matters: `if (passed)`.
		rules.some((rule) => Boolean(rule.verify(attrs)));

	it("still answers a boolean, so a deny stays a deny", () => {
		const denying = sync(
			"cedar",
			"cedar_deny",
			reporting(false, { status: "completed", revision: REVISION_A }),
		);
		expect(denying.verify(attrs)).toBe(false);
		expect(legacyEvaluate([denying])).toBe(false);
	});
});
