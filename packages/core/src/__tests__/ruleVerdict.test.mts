// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * #244: a rule backed by a policy evaluator has more to say than pass / fail —
 * whether the evaluator ran at all, and against which policy snapshot. That is
 * a fact about ONE invocation, so the only place it can come from without
 * shared mutable state is the invocation's own return value: `verify` / `decide`
 * may answer a `RuleVerdict` instead of a boolean, and `evaluate()` carries its
 * `evaluation` onto that invocation's `RuleOutcome`.
 *
 * What is pinned here is the channel, engine-neutrally: what a verdict may
 * carry, that it lands on the outcome it belongs to and on no other, and that
 * nothing unbounded crosses — a rule is third-party code and what it returns
 * ends up on the wire and in the audit log.
 */
import { describe, expect, it } from "vitest";
import { evaluate } from "../evaluate.mjs";
import { FailureRecord } from "../failureSource.mjs";
import {
	type AnyRule,
	type AsyncRule,
	type Attributes,
	POLICY_REVISION_MAX_LENGTH,
	type Rule,
	type RuleAnswer,
	type RuleEvaluation,
	ruleAnswerPassed,
} from "../types.mjs";

const REVISION_A = `sha256:${"a".repeat(64)}`;
const REVISION_B = `sha256:${"b".repeat(64)}`;

const attrs: Attributes = new Map();

const sync = (ruleType: string, code: string, answer: () => RuleAnswer): Rule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	verify: () => answer(),
});

const async = (ruleType: string, code: string, answer: () => RuleAnswer): AsyncRule => ({
	ruleType,
	code,
	message: `Failed: ${code}`,
	async: true,
	decide: async () => answer(),
});

/** The one outcome of a single-rule decision. */
async function outcomeOf(rule: AnyRule) {
	const decision = await evaluate(attrs, [rule]);
	expect(decision.reason.groups).toHaveLength(1);
	expect(decision.reason.groups[0].evaluated).toHaveLength(1);
	return { decision, outcome: decision.reason.groups[0].evaluated[0] };
}

describe("evaluate — a rule's verdict", () => {
	it("passes a group on a verdict that passed, and carries its evaluation on the outcome", async () => {
		const evaluation: RuleEvaluation = { status: "completed", revision: REVISION_A };
		const { decision, outcome } = await outcomeOf(
			sync("cedar", "cedar_deny", () => ({ passed: true, evaluation })),
		);
		expect(decision.decision).toBe("allow");
		expect(outcome).toEqual({
			code: "cedar_deny",
			message: "Failed: cedar_deny",
			passed: true,
			evaluation,
		});
	});

	it("fails a group on a verdict that did not pass — an object is never a pass by being truthy", async () => {
		const { decision, outcome } = await outcomeOf(
			sync("cedar", "cedar_deny", () => ({
				passed: false,
				evaluation: { status: "completed", revision: REVISION_A },
			})),
		);
		expect(decision.decision).toBe("deny");
		expect(outcome.passed).toBe(false);
	});

	it("carries the evaluation of an asynchronous rule the same way", async () => {
		const evaluation: RuleEvaluation = {
			status: "completed",
			revision: null,
			loadedRevision: REVISION_A,
		};
		const { outcome } = await outcomeOf(
			async("cedar", "cedar_deny", () => ({ passed: true, evaluation })),
		);
		expect(outcome.evaluation).toEqual(evaluation);
	});

	it("reports no evaluation key for a rule that answers a boolean, or a verdict without one", async () => {
		const plain = await outcomeOf(sync("scope", "invalid_scope", () => true));
		expect(Object.keys(plain.outcome)).toEqual(["code", "message", "passed"]);

		const bare = await outcomeOf(sync("scope", "invalid_scope", () => ({ passed: true })));
		expect(Object.keys(bare.outcome)).toEqual(["code", "message", "passed"]);
	});

	it("names the satisfying rule's evaluation on satisfiedBy, which is the same outcome", async () => {
		const decision = await evaluate(attrs, [
			sync("cedar", "cedar_deny", () => ({
				passed: true,
				evaluation: { status: "completed", revision: REVISION_A },
			})),
		]);
		const group = decision.reason.groups[0];
		expect(group.passed).toBe(true);
		if (group.passed) expect(group.satisfiedBy).toBe(group.evaluated.at(-1));
	});

	it("keeps each source's evaluation on its own outcome across groups", async () => {
		// Two policy sources in one decision (#244: a single revision must not be
		// reported as though it described every rule that took part).
		const decision = await evaluate(attrs, [
			sync("cedar-a", "cedar_deny", () => ({
				passed: true,
				evaluation: { status: "completed", revision: REVISION_A },
			})),
			sync("scope", "invalid_scope", () => true),
			sync("cedar-b", "cedar_deny", () => ({
				passed: false,
				evaluation: { status: "completed", revision: REVISION_B },
			})),
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

	it("reports what each invocation answered, not what the rule answered last", async () => {
		// One rule object, asked by concurrent decisions: the evaluation is the
		// invocation's, so interleaving cannot hand one decision another's.
		let calls = 0;
		const rule = async("cedar", "cedar_deny", () => {
			const revision = calls++ % 2 === 0 ? REVISION_A : REVISION_B;
			return { passed: true, evaluation: { status: "completed", revision } };
		});
		const decisions = await Promise.all(Array.from({ length: 6 }, () => evaluate(attrs, [rule])));
		expect(decisions.map((d) => d.reason.groups[0].evaluated[0].evaluation)).toEqual(
			[REVISION_A, REVISION_B, REVISION_A, REVISION_B, REVISION_A, REVISION_B].map((revision) => ({
				status: "completed",
				revision,
			})),
		);
	});

	it("freezes a copy, so a rule that reuses one verdict object cannot rewrite a decision", async () => {
		const shared = {
			passed: true,
			evaluation: { status: "completed", revision: REVISION_A } as {
				status: "completed";
				revision: string;
			},
		};
		const { outcome } = await outcomeOf(sync("cedar", "cedar_deny", () => shared));
		shared.evaluation.revision = REVISION_B;
		expect(outcome.evaluation).toEqual({ status: "completed", revision: REVISION_A });
		expect(Object.isFrozen(outcome.evaluation)).toBe(true);
	});
});

describe("evaluate — what a verdict may carry", () => {
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
		const { outcome } = await outcomeOf(
			sync("cedar", "cedar_deny", () => ({ passed: false, evaluation })),
		);
		expect(outcome.evaluation).toEqual(evaluation);
	});

	const refused: ReadonlyArray<[string, unknown]> = [
		["a verdict without a boolean passed", { passed: "yes" }],
		["a verdict with no passed at all", { evaluation: { status: "completed", revision: null } }],
		["a verdict key the contract does not name", { passed: true, detail: { policy: "p0" } }],
		["an evaluation that is not an object", { passed: true, evaluation: "completed" }],
		["an unknown status", { passed: true, evaluation: { status: "skipped", revision: null } }],
		[
			"a revision on an evaluator that was never invoked",
			{ passed: false, evaluation: { status: "not_invoked", revision: REVISION_A } },
		],
		[
			"a loaded revision on an evaluator that was never invoked",
			{ passed: false, evaluation: { status: "not_invoked", loadedRevision: REVISION_A } },
		],
		[
			"a completed evaluation that names no revision key",
			{ passed: true, evaluation: { status: "completed" } },
		],
		[
			"a loaded revision beside a vouched one",
			{
				passed: true,
				evaluation: { status: "completed", revision: REVISION_A, loadedRevision: REVISION_A },
			},
		],
		[
			"a revision that is a filesystem path",
			{ passed: true, evaluation: { status: "completed", revision: "/etc/policies/prod" } },
		],
		[
			"a revision that is policy text",
			{
				passed: true,
				evaluation: { status: "completed", revision: "permit(principal, action, resource);" },
			},
		],
		[
			"a revision over the length bound",
			{
				passed: true,
				evaluation: {
					status: "completed",
					revision: `sha256:${"a".repeat(POLICY_REVISION_MAX_LENGTH)}`,
				},
			},
		],
		[
			"a key the contract does not name",
			{
				passed: true,
				evaluation: { status: "completed", revision: REVISION_A, policyText: "permit(…);" },
			},
		],
	];
	it.each(refused)("refuses: %s", async (_name, answer) => {
		const failures = new FailureRecord();
		const rule = sync("cedar", "cedar_deny", () => answer as RuleAnswer);
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

	it("does not repeat a refused value in the error, which is logged", async () => {
		const secret = "permit(principal, action, resource);";
		const rule = sync("cedar", "cedar_deny", () => ({
			passed: true,
			evaluation: { status: "completed", revision: secret },
		}));
		const error = await evaluate(attrs, [rule]).catch((cause: unknown) => cause);
		expect(error).toBeInstanceOf(TypeError);
		expect(String((error as Error).message)).not.toContain(secret);
	});

	it("refuses the same from an asynchronous rule", async () => {
		const rule = async("cedar", "cedar_deny", () => ({ passed: "yes" }) as unknown as RuleAnswer);
		await expect(evaluate(attrs, [rule])).rejects.toThrow(TypeError);
	});
});

describe("ruleAnswerPassed", () => {
	it("reads a boolean as itself and a verdict by its passed", () => {
		expect(ruleAnswerPassed(true)).toBe(true);
		expect(ruleAnswerPassed(false)).toBe(false);
		expect(ruleAnswerPassed({ passed: true })).toBe(true);
		// The case a truthiness check gets wrong: a failing verdict is an object.
		expect(ruleAnswerPassed({ passed: false })).toBe(false);
	});
});
