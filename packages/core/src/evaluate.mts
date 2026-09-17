// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	rejectOnAbort,
	resolveEvaluateDeadlineMs,
	resolveRuleTimeoutMs,
} from "./collectorLimits.mjs";
import { RuleTimeoutError } from "./errors.mjs";
import type { FailureRecord, FailureSource } from "./failureSource.mjs";
import { beginRuleInvocation, type RuleResult } from "./ruleEvaluation.mjs";
import {
	type AnyRule,
	type AsyncRule,
	type Attributes,
	type Decision,
	isAsyncRule,
	type Rule,
	type RuleGroupOutcome,
	type RuleOutcome,
} from "./types.mjs";

/** Deny returned when no rule group applied to the request. */
const NO_APPLICABLE_RULE: Omit<Decision & { decision: "deny" }, "reason"> = {
	decision: "deny",
	code: "no_applicable_rule",
	message: "No applicable rule was collected for this request",
};

/** Options controlling evaluator semantics that a deployment may override. */
export interface EvaluateOptions {
	/**
	 * Decision returned when the rule set is empty — no collector produced a rule
	 * for this request. Defaults to `"deny"`.
	 *
	 * `"allow"` is an explicit, per-deployment opt-out of default-deny and turns
	 * the engine fail-open: any request that collects no rules is permitted. Only
	 * set it for a pipeline whose authorization is enforced elsewhere.
	 */
	onEmptyRuleSet?: "deny" | "allow";
	/**
	 * Milliseconds one asynchronous rule may take to answer (#225). Defaults to
	 * `DEFAULT_RULE_TIMEOUT_MS`; refused when not a positive whole number a
	 * timer can hold, before any rule runs. A synchronous rule is not timed.
	 */
	ruleTimeoutMs?: number;
	/**
	 * Milliseconds the whole rule phase may take — every asynchronous rule of
	 * the decision together. Defaults to `DEFAULT_EVALUATE_DEADLINE_MS`; refused
	 * like `ruleTimeoutMs`. An asynchronous rule runs under whichever of the two
	 * ends first, and none starts once the phase is spent.
	 */
	evaluateDeadlineMs?: number;
	/** The caller's signal; when it aborts, the asynchronous rule in flight is aborted with its reason. */
	signal?: AbortSignal;
	/**
	 * Where this decision's failures are recorded (#200) — which rule threw,
	 * rejected or overran a rule budget. The same record the decision's two
	 * collects were handed; see `FailureRecord`. Omitted, nothing is recorded.
	 */
	failures?: FailureRecord;
}

/**
 * Evaluates collected rules against attributes and returns an allow/deny decision.
 *
 * Semantics: rules are grouped by `ruleType`; each group is evaluated as OR
 * (any rule passing satisfies the group), and all groups must pass (AND across groups)
 * for an allow decision. On deny, the first rule of the failing group supplies
 * the `code` and `message`.
 *
 * Every decision carries a structured `reason` naming each rule group and how it
 * came out, so a caller can answer "why" without re-running the pipeline.
 *
 * An empty rule set is **denied by default**: "no rule applied" means the request
 * was never authorized, not that it needs no authorization. This matches the
 * implicit-deny semantics of OPA / OpenFGA / Cedar, so an engine swapped in behind
 * the same decision contract does not change the outcome. `onEmptyRuleSet: "allow"`
 * opts a deployment out of it.
 *
 * A rule list may carry either kind of rule (#225). A synchronous `Rule` is
 * asked through `verify`; an `AsyncRule` is awaited through `decide`, under
 * `ruleTimeoutMs`. Both are asked one at a time, in collection order, and the
 * alternatives after a group's first pass never run, whichever kind they are.
 * The evaluator is asynchronous for that reason alone — a list of synchronous
 * rules answers in the same turn, with nothing awaited but the promise itself.
 *
 * Called only once both collects have finished: the merged attributes are in
 * hand, and this is the position at which an out-of-process engine can be
 * consulted without changing when anything else happens.
 *
 * @param attrs - Attributes collected for the request (subject, resource, environment).
 * @param rules - Flat list of rules collected from all rule collectors.
 * @param options - Optional evaluator semantics overrides.
 * @returns `{ decision: "allow" }` if every group passes, otherwise a deny decision.
 * @throws {RuleTimeoutError} when an asynchronous rule overruns its budget — a
 *   deny of its own for the transport, never a pass.
 * @throws whatever a rule threw or rejected with, or the caller's abort reason,
 *   unchanged: a rule that owns its engine's outage answers `false` and logs;
 *   one that throws is reporting a fault. Which rule threw is recorded in
 *   `failures` beside the error rather than wrapped around it (#200).
 * @throws {TypeError} when a rule answers something other than a boolean, or
 *   reports an evaluation that does not read — see `beginRuleInvocation`
 *   (#244). Attributed to the rule in `failures`, like a throw.
 * @throws {RangeError} for an unusable `ruleTimeoutMs` or `evaluateDeadlineMs`,
 *   before any rule runs.
 */
export async function evaluate(
	attrs: Attributes,
	rules: AnyRule[],
	options?: EvaluateOptions,
): Promise<Decision> {
	const ruleTimeoutMs = resolveRuleTimeoutMs(options?.ruleTimeoutMs);
	const deadlineMs = resolveEvaluateDeadlineMs(options?.evaluateDeadlineMs);
	// A monotonic clock: a wall-clock step (an NTP correction) between groups
	// must not stretch or shrink the phase.
	const budget: RuleBudget = {
		ruleTimeoutMs,
		deadlineMs,
		deadlineAt: performance.now() + deadlineMs,
	};

	// Phase 1: group rules by ruleType — rules within a group are alternatives (OR).
	const groups = Map.groupBy(rules, (rule) => rule.ruleType);

	// Phase 2: nothing to evaluate → default-deny unless the deployment opted out.
	if (groups.size === 0) return emptyDecision(options);

	// Phase 3: each group must have at least one passing rule (AND across groups).
	// Every group is evaluated, including groups after the first failing one:
	// stopping early cannot report which of the remaining groups would also have
	// failed, which is the question a deny explanation exists to answer. Rules are
	// pure predicates over attributes by contract, so running them all is safe.
	const outcomes: RuleGroupOutcome[] = [];
	for (const [ruleType, groupRules] of groups) {
		outcomes.push(
			await evaluateGroup(ruleType, groupRules, attrs, budget, options?.signal, options?.failures),
		);
	}

	// Phase 4: deny names the FIRST failing group, as before; reason carries all.
	return conclude(outcomes);
}

/** Phase 2: an empty rule set is a deny unless the deployment opted out. */
function emptyDecision(options?: EvaluateOptions): Decision {
	const reason = { groups: [] };
	return options?.onEmptyRuleSet === "allow"
		? { decision: "allow", reason }
		: { ...NO_APPLICABLE_RULE, reason };
}

/** Phase 4: a deny names the FIRST failing group; reason carries all. */
function conclude(outcomes: RuleGroupOutcome[]): Decision {
	const reason = { groups: outcomes };
	const firstFailure = outcomes.find((group) => !group.passed);
	if (firstFailure) {
		const representative = firstFailure.evaluated[0];
		return {
			decision: "deny",
			code: representative.code,
			message: representative.message,
			reason,
		};
	}
	return { decision: "allow", reason };
}

/**
 * Evaluates one `ruleType` group. The group is an OR, so evaluation stops at
 * the first passing rule. `evaluated` reports exactly the rules that ran, in
 * order — on a pass that is every tried-and-failed alternative followed by the
 * passing rule (named again as `satisfiedBy`); on a fail, every alternative.
 */
/** The two bounds an asynchronous rule runs under: its own, and the phase's. */
interface RuleBudget {
	readonly ruleTimeoutMs: number;
	readonly deadlineMs: number;
	/** `performance.now()` milliseconds at which the rule phase is spent. */
	readonly deadlineAt: number;
}

async function evaluateGroup(
	ruleType: string,
	rules: AnyRule[],
	attrs: Attributes,
	budget: RuleBudget,
	caller: AbortSignal | undefined,
	failures: FailureRecord | undefined,
): Promise<RuleGroupOutcome> {
	const evaluated: RuleOutcome[] = [];
	for (const rule of rules) {
		const { passed, evaluation } = isAsyncRule(rule)
			? await runAsyncRule(rule, attrs, budget, caller, failures)
			: verifyRule(rule, attrs, failures);
		// #244: the evaluation is this invocation's, reported through the reporter
		// made for this one call — the outcome is the only place it is ever kept.
		// Absent rather than `undefined` for a rule that reported none, so such a
		// rule's outcome is key-for-key what it was.
		const outcome: RuleOutcome = {
			code: rule.code,
			message: rule.message,
			passed,
			...(evaluation !== undefined ? { evaluation } : {}),
		};
		evaluated.push(outcome);
		if (passed) return { ruleType, passed: true, evaluated, satisfiedBy: outcome };
	}
	return { ruleType, passed: false, evaluated };
}

/** How a `FailureRecord` names a rule: by the two things an operator finds it by in config. */
function ruleSource(rule: AnyRule): FailureSource {
	return { kind: "rule", ruleType: rule.ruleType, code: rule.code };
}

/**
 * Asks a synchronous rule, recording it as the source of anything it throws
 * (#200) — an answer or a report that does not read (#244) included, which is
 * as much the rule's fault as a throw is.
 */
function verifyRule(
	rule: Rule,
	attrs: Attributes,
	failures: FailureRecord | undefined,
): RuleResult {
	// One invocation, one reporter (#244): nothing the rule reports can reach
	// any outcome but this one.
	const invocation = beginRuleInvocation();
	try {
		return invocation.conclude(rule.verify(attrs, invocation.report));
	} catch (error) {
		failures?.record(error, ruleSource(rule));
		throw error;
	} finally {
		invocation.close();
	}
}

/**
 * Runs one asynchronous rule under its budget, with a signal that aborts when
 * either the budget or the caller does. Raced rather than awaited, for the
 * reason a collector is: a rule that ignores its signal would otherwise never
 * settle, and a bound only the cooperative respect is not a bound.
 *
 * The budget is the rule's own or what is left of the phase, whichever is
 * shorter, and the error names the one that tripped.
 */
async function runAsyncRule(
	rule: AsyncRule,
	attrs: Attributes,
	budget: RuleBudget,
	caller: AbortSignal | undefined,
	failures: FailureRecord | undefined,
): Promise<RuleResult> {
	if (caller?.aborted) throw caller.reason;
	const remaining = budget.deadlineAt - performance.now();
	const phaseBinds = remaining < budget.ruleTimeoutMs;
	const expired = (started: boolean) => {
		const error = phaseBinds
			? new RuleTimeoutError({
					ruleType: rule.ruleType,
					code: rule.code,
					timeoutMs: budget.deadlineMs,
					limit: "deadline",
					started,
				})
			: new RuleTimeoutError({
					ruleType: rule.ruleType,
					code: rule.code,
					timeoutMs: budget.ruleTimeoutMs,
				});
		failures?.record(error, ruleSource(rule));
		return error;
	};
	// The phase is spent: this rule is not started at all.
	if (remaining <= 0) throw expired(false);
	const own = new AbortController();
	const onCallerAbort = () => own.abort(caller?.reason);
	caller?.addEventListener("abort", onCallerAbort, { once: true });
	const timeout = setTimeout(
		() => own.abort(expired(true)),
		phaseBinds ? remaining : budget.ruleTimeoutMs,
	);
	const cancelled = rejectOnAbort(own.signal);
	// #244: this invocation's reporter. Closed in `finally`, so a rule that
	// reports after its budget is spent — or after the caller left — writes
	// to nothing.
	const invocation = beginRuleInvocation();
	try {
		return await Promise.race([
			// A rule that honours its signal rejects on abort too — with fetch's
			// AbortError, not with the reason. Whichever settles first, the
			// answer is the reason the signal carries: the timeout or the
			// caller's, never the transport's spelling of "aborted".
			//
			// Constructed rather than `Promise.resolve(rule.decide(...))`, so a
			// `decide` that throws before returning a promise is attributed
			// exactly as one that rejects (#200). A rejection after the abort is
			// the abort's, and is attributed to nobody.
			//
			// The answer is read inside the same chain (#244), so one that does
			// not read is attributed to the rule by the same `catch`.
			new Promise<unknown>((resolve) => resolve(rule.decide(attrs, own.signal, invocation.report)))
				.then((answer) => invocation.conclude(answer))
				.catch((error: unknown) => {
					if (own.signal.aborted) throw own.signal.reason;
					failures?.record(error, ruleSource(rule));
					throw error;
				}),
			cancelled.promise,
		]);
	} finally {
		invocation.close();
		clearTimeout(timeout);
		cancelled.dispose();
		caller?.removeEventListener("abort", onCallerAbort);
	}
}
